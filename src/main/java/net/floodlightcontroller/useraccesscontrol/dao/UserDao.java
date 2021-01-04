package net.floodlightcontroller.useraccesscontrol.dao;

import net.floodlightcontroller.useraccesscontrol.entity.User;
import org.slf4j.Logger;

import java.sql.*;

public class UserDao extends Dao{

    protected Connection connection;
    protected Logger logger;

    public UserDao(){}

    public UserDao(Logger log){
        this.logger = log;
        try (Connection conn = getConnection()) {
            logger.info("Database connection successful");
            /*
            User user = findUser(20161505);
            logger.info("User found: {}", user.getFullname());*/
        } catch (SQLException e) {
            logger.error("Database connection error");
            e.printStackTrace();
        }

    }

    public User findUser(Integer code){
        User user = new User();
        String query = "select u.code, u.fullname, u.idrol, u.active, u.active_timestamp, u.ip,\n" +
                "       u.mac, u.attachment_point from floodlight.user u where u.code=? limit 1";

        try(Connection connection = getConnection();
            PreparedStatement pstmt = connection.prepareStatement(query);
            ) {
            pstmt.setInt(1, code);
            try(ResultSet rs = pstmt.executeQuery();) {
                while (rs.next()){
                    user.setCode(rs.getInt(1));
                    user.setFullname(rs.getString(2));
                    user.setIdrol(rs.getInt(3));
                    user.setActive(rs.getBoolean(4));
                    Timestamp timestamp = rs.getTimestamp(5);
                    if (timestamp!=null) user.setActive_timestamp(timestamp.toLocalDateTime());
                    else user.setActive_timestamp(null);
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
        // Only Active users
        User user = null;
        String query = "select u.code, u.fullname, u.idrol, u.active, u.active_timestamp, u.ip,\n" +
                "       u.mac, u.attachment_point from floodlight.user u where u.mac=? and u.ip=? limit 1";

        try(Connection connection = getConnection();
            PreparedStatement pstmt = connection.prepareStatement(query);
        ) {
            pstmt.setString(1, mac);
            pstmt.setString(2, ip);
            try(ResultSet rs = pstmt.executeQuery();) {
                while (rs.next()){

                    user = new User();

                    user.setCode(rs.getInt(1));
                    user.setFullname(rs.getString(2));
                    user.setIdrol(rs.getInt(3));
                    user.setActive(rs.getBoolean(4));
                    Timestamp timestamp = rs.getTimestamp(5);
                    if (timestamp!=null) user.setActive_timestamp(timestamp.toLocalDateTime());
                    else user.setActive_timestamp(null);
                    user.setIp(rs.getString(6));
                    user.setMac(rs.getString(7));
                    user.setAttachment_point(rs.getString(8));

                    logger.info("User found: {}", user.getFullname());

                }
            }
        } catch (SQLException throwable) {
            throwable.printStackTrace();
        }
        return user;
    }



}
