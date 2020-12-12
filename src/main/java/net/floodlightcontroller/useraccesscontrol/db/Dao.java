package net.floodlightcontroller.useraccesscontrol.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Map;

public abstract class Dao {

    protected final String SOCKET = "localhost:3306";
    protected final String DB_NAME = "floodlight";
    protected final String USER = "gustavo";
    protected final String PASSWORD = "root";
    protected final String PARAMS = "serverTimezone=America/Lima&useSSL=false&allowPublicKeyRetrieval=true";
    protected final String URL = "jdbc:mysql://"+SOCKET+"/"+DB_NAME+"?"+PARAMS;

    public Connection getConnection() throws SQLException, ClassNotFoundException {
        Class.forName("com.mysql.cj.jdbc.Driver");
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }



}
