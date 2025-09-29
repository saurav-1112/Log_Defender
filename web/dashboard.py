import os
import sys
import streamlit as st
import sqlite3
import pandas as pd
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Path to your SQLite database
db_path = 'logs.db'

# Function to fetch logs from the database
def fetch_logs():
    conn = sqlite3.connect(db_path)  # Update the path to the correct database
    query = "SELECT * FROM logs ORDER BY id DESC"  # Modify according to your database schema
    df = pd.read_sql(query, conn)
    conn.close()
    return df

def fetch_network_logs():
    conn = sqlite3.connect(db_path)  # Update the path to the correct database
    query = "SELECT * FROM network_ip ORDER BY id DESC"  # Modify according to your database schema
    df = pd.read_sql(query, conn)
    conn.close()
    return df

# Streamlit app
def main():
    st.title("Logs Dashboard")

    # Removed the sidebar code

    # Show logs directly without using the sidebar menu
    st.subheader("Logs")
    # Fetch logs from the database
    logs_df = fetch_logs()
    network_logs_data = fetch_network_logs()

    if logs_df.empty:
        st.write("No logs available.")
    else:
        # Display logs in a Zebra table format
        st.write(logs_df)
        st.write(network_logs_data)

if __name__ == "__main__":
    main()
