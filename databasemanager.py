from dotenv import load_dotenv
import os
import psycopg2
import psycopg2.extras

load_dotenv()

class DatabaseManager:
    def get_connection(self):
        try:
            connection = psycopg2.connect(
                host=os.getenv('DATABASE_HOST'),
                port=os.getenv('DATABASE_PORT', '5432'),
                user=os.getenv('DATABASE_USER'),
                password=os.getenv('DATABASE_PASSWORD'),
                database=os.getenv('DATABASE_NAME'),
                sslmode='require'  # Neon requires SSL
            )
            
            cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            return connection, cursor
            
        except psycopg2.Error as e:
            print(f"Error connecting to the database: {e}")
            return None, None