import sqlite3
import logging

class DB():
    def __init__(self, db_file, app_logger):
        '''
        Creates a database connection

        Parameters:
            - db_file: path to the file containing the SQLite database
            - app_logger: the flask app's logger object
        '''
        self.conn = None
        self.app_logger = app_logger
        try:
            self.conn = sqlite3.connect(db_file)
        except Exception as e:
            self.app_logger.error(e)

    def run_sql(self, sql):
        '''
        Runs a SQL query against the SQLite database using the already opened connection

        Parameters:
            - sql: the sql query to execute
        Returns:
            - the result of the query
        '''
        try:
            c = self.conn.cursor()
            c.execute(sql)
            rows = c.fetchall()

            return rows
        except Exception as e:
            self.app_logger.error(e)