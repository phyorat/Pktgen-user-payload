#ifndef __STATISTIC_SQL_H__
#define __STATISTIC_SQL_H__

#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <ctype.h>

typedef struct _database_info 
{
    char *server;
    char *database;
    char *user;
    char *password;
    MYSQL *mysql;
} database_info;

#define log_message(L_ERR, fmt, ...)     printf(fmt, ##__VA_ARGS__)

int MysqlInit(const char *server, const char *database, const char *user, const char *password);

int MysqlConnect();

int MysqlClose();

int MysqlExecuteQuery(MYSQL *mysql,char *sql);

int MysqlSelectAsUInt(char *sql, unsigned int *result);

int MysqlInsert(char *sql, unsigned int *row_id);



#endif

