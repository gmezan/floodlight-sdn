package net.floodlightcontroller.useraccesscontrol.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import org.slf4j.Logger;

public abstract class Dao {

    protected final String SOCKET = "localhost:3306";
    protected final String DB_NAME = "floodlight";
    protected final String USER = "root";
    protected final String PASSWORD = "root";
    protected final String PARAMS = "serverTimezone=America/Lima&useSSL=false&allowPublicKeyRetrieval=true";
    protected final String URL = "jdbc:mysql://"+SOCKET+"/"+DB_NAME+"?"+PARAMS;

    public Connection getConnection(Logger logger) throws SQLException{
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException ex) {
            logger.error(ex.toString());
        }

        return DriverManager.getConnection(URL, USER, PASSWORD);
    }



}
