package net.floodlightcontroller.useraccesscontrol.dao;

import org.slf4j.Logger;

import java.sql.Connection;
import java.sql.SQLException;

public class UserDao extends Dao{

    protected Connection connection;

    public UserDao(Logger logger){
        try (Connection conn = getConnection(logger)) {
            logger.info("Database connection successful");
        } catch (SQLException e) {
            logger.error("Database connection error");
            e.printStackTrace();
        }
    }




}
