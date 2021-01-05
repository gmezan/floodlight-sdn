package net.floodlightcontroller.useraccesscontrol.dao;

import net.floodlightcontroller.useraccesscontrol.entity.Server;
import net.floodlightcontroller.useraccesscontrol.entity.Service;
import net.floodlightcontroller.useraccesscontrol.entity.User;
import org.slf4j.Logger;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class UserDao extends Dao{

    protected Connection connection;

    public UserDao(){
        //this.logger = log;
        try (Connection conn = getConnection()) {
            /*logger.info("Database connection successful");

            User user = findUser(20161505);
            logger.info("User found: {}", user.getFullname());*/
        } catch (SQLException e) {
            //logger.error("Database connection error");
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

                }
            }
        } catch (SQLException throwable) {
            throwable.printStackTrace();
        }
        return user;
    }

    public Server findServerByIpAndMac(String ip, String mac){
        // Only Active users
        Server server = null;
        String query = "select s.idserver, s.name, s.ip, s.mac from floodlight.server s where s.ip=? and s.mac=? limit 1";

        try(Connection connection = getConnection();
            PreparedStatement pstmt = connection.prepareStatement(query);
        ) {
            pstmt.setString(1, ip);
            pstmt.setString(2, mac);
            try(ResultSet rs = pstmt.executeQuery();) {
                while (rs.next()){

                    server = new Server();
                    server.setIdserver(rs.getInt(1));
                    server.setName(rs.getString(2));
                    server.setIp(rs.getString(3));
                    server.setMac(rs.getString(4));

                }
            }
        } catch (SQLException throwable) {
            throwable.printStackTrace();
        }
        return server;
    }

    public List<Service> findServices(User user, Server server){
        // Only Active users
        Service service = null;
        List<Service> services = new ArrayList<>();
        String query = "SELECT s.idservice, s.name, s.port, s.protocol FROM floodlight.course c inner join floodlight.course_has_service chs on (c.idcourse = chs.idcourse)\n" +
                " inner join floodlight.service s on (chs.idservice = s.idservice) \n" +
                " inner join floodlight.user_has_course uhc on (uhc.idcourse = c.idcourse) \n" +
                " where c.status = \"DICTANDO\" and uhc.code=? and s.idserver=?";

        try(Connection connection = getConnection();
            PreparedStatement pstmt = connection.prepareStatement(query);
        ) {
            pstmt.setInt(1, user.getCode());
            pstmt.setInt(2, server.getIdserver());
            try(ResultSet rs = pstmt.executeQuery();) {
                while (rs.next()){

                    service = new Service();
                    service.setIdserver(server.getIdserver());
                    service.setIdservice(rs.getInt(1));
                    service.setName(rs.getString(2));
                    service.setPort(rs.getInt(3));
                    service.setProtocol(rs.getString(4));
                    services.add(service);

                }
            }
        } catch (SQLException throwable) {
            throwable.printStackTrace();
        }
        return services;
    }




}
