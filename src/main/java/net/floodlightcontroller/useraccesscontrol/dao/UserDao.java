package net.floodlightcontroller.useraccesscontrol.dao;

import net.floodlightcontroller.useraccesscontrol.entity.User;
import org.slf4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDao extends Dao{

    protected Connection connection;
    protected Logger logger;

    public UserDao(){}

    public UserDao(Logger log){
        this.logger = log;
        try (Connection conn = getConnection()) {
            logger.info("Database connection successful");
            User user = findUser(20161505);
            logger.info("User found: {}", user.getFullname());
        } catch (SQLException e) {
            logger.error("Database connection error");
            e.printStackTrace();
        }

    }

    public User findUser(Integer code){
        User user = new User();
        String query = "select u.code, u.fullname, u.idrol, u.active, u.active_timestamp, u.ip,\n" +
                "       u.mac, u.attachment_point from user u where u.code=? limit 1";

        try(Connection connection = getConnection();
            PreparedStatement pstmt = connection.prepareStatement(query);
            ) {
            logger.info("Preparing statement");
            pstmt.setInt(1, code);

            try(ResultSet rs = pstmt.executeQuery();) {
                logger.info("Result set got");
                while (rs.next()){
                    user.setCode(rs.getInt(1));
                    user.setFullname(rs.getString(2));
                    user.setIdrol(rs.getInt(3));
                    user.setActive(rs.getBoolean(4));
                    user.setActive_timestamp(rs.getTimestamp(5).toLocalDateTime());
                    user.setIp(rs.getString(6));
                    user.setMac(rs.getString(7));
                    user.setAttachment_point(rs.getString(8));
                }
            }

        } catch (SQLException throwable) {
            throwable.printStackTrace();
        }

        return user;
    }

    public User findUserByIpAndMac(String ip, String mac){
        User user = new User();
        String query = "";

        return user;
    }



}
