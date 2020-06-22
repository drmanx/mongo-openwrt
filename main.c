/***************************************************************************
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <curl/curl.h>
#include <jansson.h>
#include <libbson-1.0/bson.h>
#include <libmongoc-1.0/mongoc.h>
#include <sqlite3.h> 

#define AGENTNAME "iptrax/0.1"
#define JSONFILECONNECTIONS "iptrax/0.1"
#define SOCKSPROXY "socks5h://127.0.0.1:29050"
#define LUCICREDS "luci_username=root&luci_password="
#define MONGODBHOST "mongodb://127.0.0.1:27017"
#define SQLITEDBFILE "/tmp/iptrack.db"

static const char *bodyfilename = "/tmp/iptrack.out";

static int runsystemcommand()
{
   char command[240];

   strcpy( command, "ls -l /tmp/" );
   system(command);
   return(0);
}

static int traceroutesystem()
{
	printf("#### function traceroutesystem ####");
	FILE *fp;
	char iptracetodo = '1.1.1.1';
	char iptrace[1035];
    char command[240];
    char iptracerouteout[50][100];
	strcpy(command, "/usr/bin/traceroute 1.1.1.1" );

  /* Open the command for reading. */
  fp = popen(command, "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  int iptracecount = 0;
  
  /* Read the output a line at a time - output it. */
  while (fgets(iptrace, sizeof(iptrace), fp) != NULL) {
    //printf("#### iptrace1: %s", iptrace);
    strcpy(iptracerouteout[iptracecount], iptrace);
	//strcpy(iptracerouteoutall[1035], iptracerouteout[iptracecount]);
    printf("#### iptrace2: %s", iptracerouteout[iptracecount]);
    iptracecount++;
  }
  /* close */
  pclose(fp);
  return 0;
}

static int runsystemcommandoutput()
{
	printf("#### function runsystemcommandoutput ####");
	//#include <stdio.h>
	//#include <stdlib.h>

  FILE *fp;
  char path[1035];

  /* Open the command for reading. */
  fp = popen("/bin/ls /etc/", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path), fp) != NULL) {
    printf("%s", path);
  }

  /* close */
  pclose(fp);
  return 0;
}

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("##### %s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

static int sqlconnect(sqlite3 *db)
{
	printf("#### sqlite start ##############\n");
	//https://www.sqlite.org/cintro.html
	//https://www.tutorialspoint.com/sqlite/sqlite_c_cpp.htm
   char *sql;
   //sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   rc = sqlite3_open(SQLITEDBFILE, &db);

   if( rc ) {
      fprintf(stderr, "#### Can't open database: %s ####\n", sqlite3_errmsg(db));
      return(1);
   } else {
      fprintf(stderr, "#### Opened database successfully ####\n");
   }

   printf("#### sqlite Create SQL statement ##############\n");
   sql = "CREATE TABLE IPCONNECTIONS("  \
      "ID INTEGER PRIMARY KEY," \
      "start           DATETIME    NOT NULL," \
      "bytes           TEXT    NOT NULL," \
      "dport           TEXT    NOT NULL," \
      "dst           TEXT    NOT NULL," \
      "layer3           TEXT    NOT NULL," \
      "layer4           TEXT    NOT NULL," \
      "mark           TEXT    NOT NULL," \
      "packets            INT     NOT NULL," \
      "sport           TEXT    NOT NULL," \
      "src           TEXT    NOT NULL," \
      "timeout            INT     NOT NULL," \
      "use           TEXT    NOT NULL," \
      "zone           TEXT    NOT NULL);";

   printf("#### sqlite Execute SQL statement ##############\n");
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
   if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
      fprintf(stdout, "Table created successfully\n");
   }   
   
   sqlite3_close(db);
   printf("#### sqlite end ##############\n");
   return 0;
}	

static int connectiondel(sqlite3 *db, int keyidtodelete)
{
   printf("#### function connectiondel DELETE %d #####\n", keyidtodelete);
   int rc;
   char *sql;
   char *zErrMsg = 0;
   const char* data = "Callback function called";
   rc = sqlite3_open(SQLITEDBFILE, &db);

   if( rc ) {
      fprintf(stderr, "#### Can't open database: %s ####\n", sqlite3_errmsg(db));
      return(1);
   } else {
      fprintf(stderr, "#### Opened database successfully ####\n");
   }
   
   sql = sqlite3_mprintf("DELETE FROM IPCONNECTIONS WHERE ID = %d;", keyidtodelete);
   rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
      if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
      fprintf(stdout, "#### DELETE Completed\n");
   }
   
   sqlite3_close(db);
   return 1;
}

static int connectioncheckexistsqlite(sqlite3 *sqlitedb, json_t *connections)
{
   printf("#### function connectioncheckexistsqlite #####\n");
   //compare whats in sqldb, to current connections. if db version doesn't exist in current connections send to mongodb then delete

   int rc;
   char *sql;
   char *zErrMsg = 0;
   const char* data = "Callback function called";
   const char *cchardport,*cchardst,*ccharsport,*ccharsrc, *cchardatestart;//, *connectionmatchedsqlid;
   const int *connectionsqlid;
   sqlite3_stmt    *stmt = NULL;
   json_t *connectioncur, *connectionmatchedcur , *jsoncurrent;

   rc = sqlite3_open(SQLITEDBFILE, &sqlitedb);
   if( rc ) {
      fprintf(stderr, "#### Can't open database: %s ####\n", sqlite3_errmsg(sqlitedb));
      return(1);
   } else {
      fprintf(stderr, "#### Opened database successfully ####\n");
   }

   /* Create SQL statement */
   sql = sqlite3_mprintf("SELECT * FROM IPCONNECTIONS");
   /* Execute SQL statement */
   rc = sqlite3_prepare_v2( sqlitedb, sql, -1, &stmt, &zErrMsg);
   if ( rc != SQLITE_OK) exit( -1 );
   //sqlite3_close(sqlitedb);

   int connectionmatched = 0;
   //int connectioncount;// = 0;
   int connectionmatchedsqlid = 0;
   int jsonarraysize = json_array_size(connections);

   int DeleteCount = 0;
   int DeleteArray[ jsonarraysize ];
   int sqlite3_stepper = 0;

   while( sqlite3_step( stmt ) == SQLITE_ROW ) {
        printf("#### while sqlite loop start jsonarraysize:%d ##############\n", jsonarraysize);
        connectionmatched = 0;
		connectionsqlid = (const int*)sqlite3_column_int( stmt, 0 );//sqlid
		cchardatestart = (const char*)sqlite3_column_int( stmt, 1 );//datestart
        cchardport = (const char*)sqlite3_column_text( stmt, 3 );//dport3
        cchardst = (const char*)sqlite3_column_text( stmt, 4 );//dst4
        ccharsport = (const char*)sqlite3_column_text( stmt, 9 );//sport9
        ccharsrc = (const char*)sqlite3_column_text( stmt, 10 );//src10

        printf( "#### sqlquery current entry: %s %s %s %s ####\n", cchardport, cchardst, ccharsport, ccharsrc);
		printf("####### compare to currentconnections ###########\n");
        for(int connectioncount = 0; connectioncount < jsonarraysize -1; connectioncount++)
        {
            connectioncur = json_array_get(connections, connectioncount);
			jsoncurrent = json_object_get( connectioncur, "dport" );
			const char* cstrdport = json_string_value(jsoncurrent);
			jsoncurrent = json_object_get( connectioncur, "dst" );
			const char* cstrdst = json_string_value(jsoncurrent);
			jsoncurrent = json_object_get( connectioncur, "sport" );
			const char* cstrsport = json_string_value(jsoncurrent);
			jsoncurrent = json_object_get( connectioncur, "src" );
			const char* cstrsrc = json_string_value(jsoncurrent);

			if ((strcmp(cstrdport, cchardport) == 0) && (strcmp(cstrdst, cchardst) == 0) && (strcmp(cstrsport, ccharsport) == 0) && (strcmp(cstrsrc, ccharsrc) == 0))
			{
				printf("##### compared sql to current connection and matched\n");
				//connectionmatchedsqlid = connectioncount;//sqlid
				printf("#### connectionmatchedSQLID: cmqs:%d  count:%d ####\n", connectionmatchedsqlid, connectioncount);
				connectionmatched = 1;
				connectionmatchedcur = json_array_get(connections,connectioncount);			
				connectioncount = jsonarraysize;//force for loop to exit
			}
        }

		if (connectionmatched == 0)
		{
			printf("#### connection has FINISHED remove from sqlite, and insert to mongodb ####\n");
			printf("#### ADD TO DELETEARRAY %d ####\n", connectionsqlid);	//deletesql
			DeleteArray[ DeleteCount ] = connectionsqlid;
			DeleteCount++;

			//connectiondel(sqlitedb, connectionmatchedsqlid);
			printf("#### existsql dump connectioncur before mongo submit ##############\n");
			json_dump_file(connectionmatchedcur, "/tmp/jsondump_existsql_connectionmatchedcur.out", 0644);	
			//printf("#### submit to mongodb next %s ####\n", sizeof(connectionmatchedcur));
			connectionaddmongo(connectionmatchedcur, cchardatestart);//add to mongodb with ip startdate
		} else {
			printf("#### connection already in sqlitedb DO NOTHING? ####\n");				
		}
		//connectionmatchedsqlid = 1;
        printf("#### for connections loop end ##############\n");
   }
   printf("#### while sqlite & connections loop end ##############\n");
   //free(rc);
   //free(sql);
   sqlite3_finalize(stmt);
   sqlite3_close(sqlitedb);

   printf("#### function connectioncheckexistsqlite end #####\n");
   printf("#### DeleteCount: %d ####\n", DeleteCount);
   for(int DeleteCounter = 0; DeleteCounter < DeleteCount; DeleteCounter++)
   {
      printf("#### DeleteCounter: %d ItemToDel %d####\n", DeleteCounter, DeleteArray[DeleteCounter]);
      connectiondel(sqlitedb, DeleteArray[DeleteCounter]);
   }
//	printf("#### DELETE TRY TO DELETE WITHOUT LOCK? ####\n");
//  connectiondel(sqlitedb, 1);
   return 1;
   return 0;
}

int connectioncheckexists(sqlite3 *db, json_t *connectioncur)
{
   //printf("#### function connectioncheckexists #####\n");
   int rc;
   char *sql;
   char *zErrMsg = 0;
   const char* data = "Callback function called";
   sqlite3_stmt    *stmt = NULL;

   json_t *jsoncurrent;
   jsoncurrent = json_object_get( connectioncur, "dport" );
   char *cstrdport = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "dst" );
   char *cstrdst = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "sport" );
   char *cstrsport = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "src" );
   char *cstrsrc = json_string_value(jsoncurrent);
   
   rc = sqlite3_open(SQLITEDBFILE, &db);
   if( rc ) {
      fprintf(stderr, "#### Can't open database: %s ####\n", sqlite3_errmsg(db));
      return(1);
   } else {
      fprintf(stderr, "#### Opened database successfully ####\n");
   }

   /* Create SQL statement */
   sql = sqlite3_mprintf("SELECT count(*) from IPCONNECTIONS where (dport = '%q' and dst = '%q' and sport = '%q' and src = '%q')", cstrdport, cstrdst, cstrsport, cstrsrc);

   /* Execute SQL statement */
   rc = sqlite3_prepare_v2( db, sql, -1, &stmt, &zErrMsg);
   if ( rc != SQLITE_OK) exit( -1 );

   int resultz;
   while( sqlite3_step( stmt ) == SQLITE_ROW ) {
        data = (const char*)sqlite3_column_text( stmt, 0 );
//        printf( "## %s\n", data ? data : "[NULL]" );
        resultz = atoi(data ? data : "[NULL]");
   }
   //printf("#### result in function:= %d\n", resultz);
   sqlite3_finalize( stmt );
   //printf("#### function connectioncheckexists end #####\n");
   return resultz;
}

int connectionaddmongo(json_t *connectioncur, char* datestart)
{
   printf("#### function connectionaddmongo start #####\n");
        const char *uri_string = MONGODBHOST;
        mongoc_uri_t *uri;
        mongoc_client_t *client;
        mongoc_database_t *database;
        mongoc_collection_t *collection;
        bson_t *command, reply, *insert;
        bson_error_t bsonerror;
        char *str;
        bool retval;
        json_t *jsoncurrent;

        printf("#### mongodb init: Required to initialize libmongoc's internals ##############\n");
        mongoc_init ();

        uri = mongoc_uri_new_with_error (uri_string, &bsonerror);
        if (!uri) {
            fprintf (stderr,
                     "failed to parse URI: %s\n"
                     "error message:       %s\n",
                     uri_string, bsonerror.message);
            return EXIT_FAILURE;
        }

        printf("#### mongodb init: Create a new client instance ##############\n");
        client = mongoc_client_new_from_uri (uri);
        if (!client) {
            return EXIT_FAILURE;
        }

        printf("#### mongodb client db/collection setup ##############\n");
        mongoc_client_set_appname (client, "iptrack");
        database = mongoc_client_get_database (client, "iptrack");
        collection = mongoc_client_get_collection (client, "iptrack", "events");

        printf("#### mongodb ping ##############\n");
        command = BCON_NEW ("ping", BCON_INT32 (1));
        retval = mongoc_client_command_simple (client, "admin", command, NULL, &reply, &bsonerror);
        if (!retval) {
            fprintf (stderr, "%s\n", bsonerror.message);
            return EXIT_FAILURE;
        }

			bson_t bisondoc;
			bson_init (&bisondoc);
        	//bson_append_utf8 (&bisondoc, "key", -1, "value", -1);

        printf("#### mongodb get epoc datetime ##############\n");
			struct timeval tv;
			gettimeofday(&tv, NULL);
			unsigned long long millisecondsSinceEpoch = 
				(unsigned long long)(tv.tv_sec) * 1000 +
				(unsigned long long)(tv.tv_usec) / 1000;

        printf("#### mongodb dump connectioncur ##############\n");
        json_dump_file(connectioncur, "/tmp/jsondump_addmongo_connectioncur.out", 0644);
        //printf("#### mongodb insert connections bson_append ##############\n");
        //    BSON_APPEND_DATE_TIME (&bisondoc, "datetimestart", millisecondsSinceEpoch);
            BSON_APPEND_DATE_TIME (&bisondoc, "datetimestart", datestart);
        //printf("#### mongodb insert connections bson_append ##############\n");
            BSON_APPEND_DATE_TIME (&bisondoc, "datetimeend", millisecondsSinceEpoch);
        //printf("#### mongodb insert connections bson_append1 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "bytes" );
            BSON_APPEND_INT64 (&bisondoc, "bytes", json_number_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append2 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "dport" );
            BSON_APPEND_UTF8 (&bisondoc, "dport", json_string_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append3 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "dst" );
            //printf( "#### dst json_string_value %s\n", json_string_value(jsoncurrent));
            BSON_APPEND_UTF8 (&bisondoc, "dst", json_string_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append4 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "layer3" );
            BSON_APPEND_UTF8 (&bisondoc, "layer3", json_string_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append5 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "layer4" );
            BSON_APPEND_UTF8 (&bisondoc, "layer4", json_string_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append6 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "mark" );
            BSON_APPEND_UTF8 (&bisondoc, "mark", json_string_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append7 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "packets" );
            BSON_APPEND_INT64 (&bisondoc, "packets", json_number_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append8 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "sport" );
            BSON_APPEND_UTF8 (&bisondoc, "sport", json_string_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append9 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "src" );
            BSON_APPEND_UTF8 (&bisondoc, "src", json_string_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append10 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "timeout" );
            BSON_APPEND_INT64 (&bisondoc, "timeout", json_number_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append11 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "use" );
            BSON_APPEND_UTF8 (&bisondoc, "use", json_string_value(jsoncurrent));
        //printf("#### mongodb insert connections bson_append12 ##############\n");
            jsoncurrent = json_object_get( connectioncur, "zone" );
            BSON_APPEND_UTF8 (&bisondoc, "zone", json_string_value(jsoncurrent));

        printf("#### mongodb mongoc_collection_insert_one  ##############\n");
            if (!mongoc_collection_insert_one (collection, &bisondoc, NULL, NULL, &bsonerror)) {
                    fprintf (stderr, "#### %s\n", bsonerror.message);
            }
        printf("#### mongodb cleanup ##############\n");

        printf("#### Release our handles and clean up libmongoc\n");
        mongoc_collection_destroy (collection);
        mongoc_database_destroy (database);
        mongoc_uri_destroy (uri);
        mongoc_client_destroy (client);
        mongoc_cleanup ();

        printf("#### mongodb end ##############\n");
		printf("#### function connectionaddmongo end #####\n");
        return 1;
}

int connectionadd(sqlite3 *db,json_t *connectioncur)
{
   int rc;
   char *sql;
   char *zErrMsg = 0;
   //sqlite3 *db;

   rc = sqlite3_open(SQLITEDBFILE, &db);

   if( rc ) {
      fprintf(stderr, "#### Can't open database: %s ####\n", sqlite3_errmsg(db));
      return(1);
   } else {
      fprintf(stderr, "#### Opened database successfully ####\n");
   }

   json_t *jsoncurrent;
   jsoncurrent = json_object_get( connectioncur, "bytes" );
   double cdoublebytes = json_number_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "dport" );
   char *cstrdport = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "dst" );
   char *cstrdst = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "layer3" );
   char *cstrlayer3 = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "layer4" );
   char *cstrlayer4 = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "mark" );
   char *cstrmark = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "packets" );
   double cdoublepackets = json_number_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "sport" );
   char *cstrsport = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "src" );
   char *cstrsrc = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "timeout" );
   double cdoubletimeout = json_number_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "use" );
   char *cstruse = json_string_value(jsoncurrent);
   jsoncurrent = json_object_get( connectioncur, "zone" );
   char *cstrzone = json_string_value(jsoncurrent);

   sql = sqlite3_mprintf("INSERT INTO IPCONNECTIONS (id,start,bytes,dport,dst,layer3,layer4,mark,packets,sport,src,timeout,use,zone) "  \
         "VALUES (null,DateTime('now'),'%f','%q','%q','%q','%q','%q','%f','%q','%q','%f','%q','%q' );", \
         cdoublebytes,cstrdport,cstrdst,cstrlayer3,cstrlayer4,cstrmark,cdoublepackets, cstrsport, cstrsrc, cdoubletimeout, cstruse, cstrzone);

   //printf("#### sqlite Execute SQL statement ##############\n");
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
   if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
      fprintf(stdout, "#### Insert Completed\n");
   }
   
   sqlite3_close(db);
   printf("#### sqlite end ##############\n");
   return 1;
}


static int connectionsget(void)
{
	CURL *curl;
    CURLcode res;
    CURLcode rescookies;

	static const char *OPENWRTURLFULL = "http://192.168.1.1/cgi-bin/luci/admin/status/realtime/connections_status";

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(curl) {
        char nline[256];

        curl_easy_setopt(curl, CURLOPT_URL, OPENWRTURLFULL);
        //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, ""); /* start cookie engine */
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L); /* no progress meter please */
        //curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data); /* send all data to this function  */
        curl_easy_setopt(curl, CURLOPT_COOKIELIST, "ALL");
        //curl_easy_setopt(curl, CURLOPT_PROXY, SOCKSPROXY);

        curl_easy_setopt(curl, CURLOPT_USERAGENT, AGENTNAME);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, LUCICREDS);
        //fprintf(stdout, "### NLINE: %s ###\n", nline);

        printf("#### Curl Do request for sysauth! ##############\n");
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "Curl perform failed: %s\n", curl_easy_strerror(res));
            return 1;
        }
        //print_cookies(curl);
        FILE *bodyfile;

        /* open the body file */
        bodyfile = fopen(bodyfilename, "wb");
        if(!bodyfile) {
            curl_easy_cleanup(curl);
            fclose(bodyfile);
            return -1;
        }
        fprintf(bodyfile, "[\n");
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, bodyfile);
        printf("#### curl do request to get connection ############\n");
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "Curl perform failed: %s\n", curl_easy_strerror(res));
            return 1;
        }
        fprintf(bodyfile, "\n]\n");
        fclose(bodyfile);
        printf("#### Output file to %s complete ##############\n", bodyfilename);
    }
    else {
        fprintf(stderr, "Curl init failed!\n");
        return 1;
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
	return 0;
}

static int connectionsprocess(sqlite3 *sqlitedb)
{
    printf("#### json vars ##############\n");
    json_t *root;
    json_error_t error;

    printf("#### json load ##############\n");
    //root = json_loads(curl, 0, &error);
	root = json_load_file(bodyfilename, 0, &error);

    printf("#### json simple error check ##############\n");
    if(!root)
    {
		fprintf(stderr, "### error: on line %d: %s\n", error.line, error.text);
        return 1;
    }

    if(!json_is_array(root))
    {
       fprintf(stderr, "### error: root is not an array\n");
       json_decref(root);
       return 1;
     }
        printf("#### json quick start ##############\n");
        json_t *data, *connections, *connectioncur, *jsoncurrent;

        data = json_array_get( root, 0 );
        connections = json_object_get( data, "connections" );
        json_dump_file(connections, "/tmp/jsondump_connections.out", 0644);

        printf("#### connections loop start ##############\n");
        int connectioncount;
        int connectionexists;
        for(connectioncount = 0; connectioncount < (json_array_size(connections) - 0 ); connectioncount++)
        {
            connectioncur = json_array_get( connections, connectioncount );
            //printf("#### mongodb insert sqllitecall start ##############\n");
			//printf("#### main connectioncheckexists start ##############\n");

			connectionexists = connectioncheckexists(sqlitedb, connectioncur);
			//printf("#### result out function:= %d\n", connectionexists);
			if(connectionexists == 0) {
				fprintf(stdout, "#### New Connection, insert in to sqlitedb\n");
				//connectionadd(sqlitedb, json_array_get( connections, connectioncount ));
				connectionadd(sqlitedb, connectioncur);
			} else {
				fprintf(stdout, "#### Connection already exists skip sqlitedb\n");
				//printf("#### main connectioncheckexists start ##############\n");
				//connectionaddmongo(connectioncur);
				//printf("#### mongodb insert sqllitecall end ##############\n");
			}
        }
        printf("#### connections loop end ##############\n");
        printf("#### call connectioncheckexistsqlite from connectionprocess ##############\n");
        connectioncheckexistsqlite(sqlitedb, connections);

}

static void print_cookies(CURL *curl)
{
    CURLcode res;
    struct curl_slist *cookies;
    struct curl_slist *nc;
    int i;

    printf("Cookies, curl knows:\n");
    res = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
    if(res != CURLE_OK) {
        fprintf(stderr, "Curl curl_easy_getinfo failed: %s\n",
                curl_easy_strerror(res));
        exit(1);
    }
    nc = cookies;
    i = 1;
    while(nc) {
        printf("[%d]: %s\n", i, nc->data);
        nc = nc->next;
        i++;
    }
    if(i == 1) {
        printf("(none)\n");
    }
    curl_slist_free_all(cookies);
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
    return written;
}

int main(void)
{
    sqlite3 *sqlitedb;
	printf("#### main sqlconnect start ##############\n");
	sqlconnect(sqlitedb);
	printf("#### main sqlconnect end ##############\n");

		printf("#### main connectionsget start ##############\n");
		connectionsget();
		printf("#### main connectionsget end ##############\n");

		printf("#### main connectionsprocess start ##############\n");
		connectionsprocess(sqlitedb);
		printf("#### main connectionsprocess end ##############\n");

		printf("#### main runsystemcommand start ##############\n");
		runsystemcommand();
		printf("#### main runsystemcommand end ##############\n");

		printf("#### main runsystemcommandoutput start ##############\n");
		//runsystemcommandoutput();
		printf("#### main runsystemcommandoutput end ##############\n");

		printf("#### main traceroutesystem start ##############\n");
		//traceroutesystem();
		printf("#### main traceroutesystem end ##############\n");

		printf("#### usleep at end of main loop ##############\n");
    sqlite3_close(sqlitedb);
    printf("#### end before return ##############\n");
    return 0;
}
