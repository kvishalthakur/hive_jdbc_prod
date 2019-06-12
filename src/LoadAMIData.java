import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.TimeZone;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import com.apporchid.hive.BasicFormatterImpl;
import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;
import com.google.gson.JsonParser;

public class LoadAMIData
{
  private static String intervalSuffix = "";

  private static final String PROGRAM_CONFIGURATION_PROPERTIES_FILE_NAME = System.getProperty("ami.config.file", "application.properties");
  private static final String CONTENT_TYPE_ALERTS_REST = "application/json; charset=utf-8";
  private static final Boolean IS_LOG_QUERY = Boolean.valueOf(Files.exists(Paths.get("/apporchid/ami_jobs/.debug.ami", new String[0]), new LinkOption[] { LinkOption.NOFOLLOW_LINKS }));

  public static Logger logger = Logger.getRootLogger();

  private static PropertiesConfiguration applicationConfig = null;

  private static HttpClient client = null;

  static
  {
    if (System.getProperty("skipDefaults", "false").matches("true|TRUE|True|1|hanji|yes|Yes|YES")) {
      System.setProperty("HADOOP_HOME", "C:\\hadoop\\");
      System.setProperty("hadoop.home.dir", "C:\\hadoop\\");
      System.setProperty("java.security.krb5.conf", "C:\\programs\\java\\hive-jdbc\\krb5.ini");
    }

    System.setProperty("sun.security.krb5.debug", "true");
    try {
      initialize();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void initialize()
    throws Exception
  {
    System.out.println("+===============================================+");
    System.out.println("+ ami.config.file ==> " + PROGRAM_CONFIGURATION_PROPERTIES_FILE_NAME);
    System.out.println("+==============================================+");

    Path path = Paths.get(PROGRAM_CONFIGURATION_PROPERTIES_FILE_NAME, new String[0]);
    Charset charset = StandardCharsets.UTF_8;
    try
    {
      String content = new String(Files.readAllBytes(path), charset);
      content = content.replaceAll("\\\\,", ",");
      content = content.replaceAll(",", "\\\\,");
      Files.write(path, content.getBytes(charset), new OpenOption[0]);
    } catch (IOException e1) {
      e1.printStackTrace();
      throw e1;
    }
    try
    {
      String content;
      applicationConfig = new PropertiesConfiguration(PROGRAM_CONFIGURATION_PROPERTIES_FILE_NAME);
      logger.info("This program will try to connect to the source cluster =>" + applicationConfig.getString("ami.pipelines.config.hive_clusterName"));

      applicationConfig.setDelimiterParsingDisabled(true);

      boolean isGrantTypePassword = getConfigValue(ApplicationConfig.AMI_SECUREAUTH_CONFIG_GRANT_TYPE).equals("password");

      for (ApplicationConfig a : ApplicationConfig.values()) {
        logger.info(" :: app_config => key : " + a.getKey() + " || value : '" + (a.getKey().matches(".*password.*|.*secret.*") ? "xxxxxxxxxxxx" : IS_LOG_QUERY.booleanValue() ? "sha256://" + Hashing.sha256().hashString(getConfigValue(a), StandardCharsets.UTF_8) : getConfigValue(a)) + "'");
        if (a.getKey().contains("optional")) {
          if ((isGrantTypePassword) && (a.getKey().matches(".*username|.*password")))
            Objects.requireNonNull(getConfigValue(a), "Cannot proceed. Incomplete configuration, Secure Auth grant type is password, config expected grant username / password to be available => '" + a.getKey() + "' in " + PROGRAM_CONFIGURATION_PROPERTIES_FILE_NAME);
        }
        else
          Objects.requireNonNull(getConfigValue(a), "Cannot proceed. Incomplete configuration, missing value for key => '" + a.getKey() + "' in " + PROGRAM_CONFIGURATION_PROPERTIES_FILE_NAME);
      }
    }
    catch (ConfigurationException e) {
      logger.warn("Can't initialize stub application - reason =" + e.getMessage());
      logger.error(e, e.getCause());
      throw e;
    }
    try
    {
      client = HttpClients.custom().setSslcontext(new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy()
      {
        public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException
        {
          return true;
        }
      }).build()).setDefaultHeaders(Lists.newArrayList(new BasicHeader[] { 
        new BasicHeader("Accept", "application/json") })).build();
    } catch (Exception e) {
      e.printStackTrace();
      throw e;
    }
  }

  public static String getConfigValue(ApplicationConfig c)
  {
    return applicationConfig.getString(c.getKey());
  }

  public static void maina(String[] args)
    throws Exception
  {
    System.out.println(String.format("alerts audit (true) t=%s | r=%s | ri=%s | ei1=%s | ei2=%s | ei3=%s ", new Object[] { "foo", "bar", "tom", "dick", "hary", "tony" }));

    System.out.println(getConfigValue(ApplicationConfig.APP_CONFIG_HIVE_JDBC_URI));
    System.out.println("jdbc:hive2://hsynlhdps202.amwaternp.net:2181,hsynlhdps200.amwaternp.net:2181,hsynlhdps201.amwaternp.net:2181/;serviceDiscoveryMode=zooKeeper;zooKeeperNamespace=hiveserver2-hive2".matches(getConfigValue(ApplicationConfig.APP_CONFIG_HIVE_JDBC_URI)));
    System.out.println("jdbc:hive2://staplhdpsm002.amwater.net:2181,staplhdpsm005.amwater.net:2181,staplhdpsm006.amwater.net:2181,staplhdpsm003.amwater.net:2181,staplhdpsm004.amwater.net:2181/;serviceDiscoveryMode=zooKeeper;zooKeeperNamespace=hiveserver2-hive2".matches(getConfigValue(ApplicationConfig.APP_CONFIG_HIVE_JDBC_URI)));
  }

  public static void main(String[] args) throws Exception
  {
    System.setProperty("java.net.debug", "true");

    boolean loadHourlyData = Boolean.parseBoolean(System.getProperty("ami.isLoadHourlyData", "false"));
    boolean loadDailyData = Boolean.parseBoolean(System.getProperty("ami.isLoadDailyData", "false"));
    
    boolean loadHourlyDataWV = Boolean.parseBoolean(System.getProperty("ami.isLoadHourlyDataWV", "false"));
    boolean loadDailyDataWV = Boolean.parseBoolean(System.getProperty("ami.isLoadDailyDataWV", "false"));
    
    boolean runHighUsageAlerts = Boolean.parseBoolean(System.getProperty("ami.isRunHighUsageAlerts", "false"));
    boolean runLeakAlerts = Boolean.parseBoolean(System.getProperty("ami.isRunLeakAlerts", "false"));
    boolean isUpdateMeterNextRead = Boolean.parseBoolean(System.getProperty("ami.isUpdateMeterNextRead", "false"));
    boolean isRunUsagePrediction = Boolean.parseBoolean(System.getProperty("ami.isRunUsagePrediction", "false"));

    Connection pgConn = null;
    Connection hiveConn = null;

    pgConn = getPostgresConnection(getConfigValue(ApplicationConfig.APP_CONFIG_PG_DB_SINK_JDBC_URI), getConfigValue(ApplicationConfig.APP_CONFIG_PG_DB_SINK_USERNAME), getConfigValue(ApplicationConfig.APP_CONFIG_PG_DB_SINK_PASSWORD));

    boolean isZookeeperConnected = false;
    if (loadHourlyData) {
      hiveConn = zookeeperConnect();
      isZookeeperConnected = true;
      updateHourlyData(hiveConn, pgConn);
    }

    if (loadDailyData) {
      if (!isZookeeperConnected) {
        hiveConn = zookeeperConnect();
      }
      updateDailyData(hiveConn, pgConn);
    }
    
    if (loadHourlyDataWV) {
        if (!isZookeeperConnected) {
          hiveConn = zookeeperConnect();
        }
        updateHourlyDataWV(hiveConn, pgConn);
    }
    if (loadDailyDataWV) {
        if (!isZookeeperConnected) {
          hiveConn = zookeeperConnect();
        }
        updateDailyDataWV(hiveConn, pgConn);
      }

    if (isUpdateMeterNextRead) {
      if (!isZookeeperConnected) {
        hiveConn = zookeeperConnect();
      }
      updateMeterNextRead(hiveConn, pgConn);
    }

    if (isRunUsagePrediction) {
      System.out.println("Running Usage Prediction Algorithm begin at " + LocalDateTime.now());
      double zScore = Double.parseDouble(getConfigValue(ApplicationConfig.APP_CONFIG_USAGE_PREDICTION_ZEE_SCORE_SIGMA));

      updateUsagePrediction(pgConn, Double.valueOf(zScore));
      System.out.println("Running Usage Prediction Algorithm ends at " + LocalDateTime.now());
    }

    if (runHighUsageAlerts) {
      System.out.println("High Usage Calculation started at " + new Date());
      double zScore = 
        Double.parseDouble(getConfigValue(ApplicationConfig.APP_CONFIG_HIGHUSAGEALERT_ZEE_SCORE_SIGMA));
      int numOfPastMonths = 
        Integer.parseInt(getConfigValue(ApplicationConfig.APP_CONFIG_HIGHUSAGEALERT_NUMBER_OF_PAST_MONTHS));
      int minimumUsage = 
        Integer.parseInt(getConfigValue(ApplicationConfig.APP_CONFIG_HIGHUSAGEALERT_MINIMUM_USAGE));
      getHighUsage(pgConn, zScore, numOfPastMonths, minimumUsage);
    }

    if (runLeakAlerts) {
      System.out.println("Leaks Calculation started at" + new Date());
      int intervalHours = Integer.parseInt(getConfigValue(ApplicationConfig.APP_CONFIG_LEAKALERT_INTERVALHOURS));
      int minimumConsumption = Integer.parseInt(getConfigValue(ApplicationConfig.APP_CONFIG_LEAKALERT_MINIMUMCONSUMPTION));
      getLeaks(pgConn, intervalHours, minimumConsumption);
    }

    if (hiveConn != null) {
      hiveConn.close();
    }

    if (pgConn != null) {
      pgConn.close();
    }
    logger.debug("finished at " + new Date());
    logger.info("LAB => PROD");
  }

  private static void getLeaks(Connection pgConn, int intervalHours, int minimumConsumption) throws Exception {
    String leaksSQL = "select businesspartnernumber,contractaccount from app.meter_ami_reads where read_interval_type = 'HOURLY" + 
      intervalSuffix + "'  " + 
      "and reading_datetime> current_timestamp - interval '" + intervalHours + " hour' " + 
      "group by businesspartnernumber,contractaccount " + 
      "having min(consumption)> " + minimumConsumption;

    debugQuery(leaksSQL);
    ResultSet rs2 = pgConn.createStatement().executeQuery(leaksSQL);

    String token = getSecureAuthToken();
    while (rs2.next()) {
      String businessPartner = rs2.getString(1);
      String contractAccount = rs2.getString(2);
      System.out.println(businessPartner + "," + contractAccount);
      String apiUrl = getConfigValue(ApplicationConfig.APP_CONFIG_LEAKALERT_ENDPOINT_URL);
      callLeaksRESTService(pgConn, apiUrl, AccionPayloadAmi.build(businessPartner, contractAccount), token);
    }
  }

  private static String getCountiesListSQLString() {
    StringBuffer result = new StringBuffer("");

    for (String county : getConfigValue(ApplicationConfig.APP_CONFIG_COUNTIES_LIST).split(",")) {
      result.append("'").append(county.trim()).append("',");
    }
    return StringUtils.chop(result.toString());
  }

  private static void getHighUsage(Connection pgConn, double zScore, int numOfPastMonths, int minimumUsage) throws Exception
  {
    String highUsageSQL = "SELECT mar.businesspartnernumber, mar.contractaccount, trim(leading '0' FROM mar.equipmentnumber) , mr2.last_read_time, sum(mar.consumption), ami_calc.high_usage_limit FROM app.meter_ami_reads mar JOIN ( SELECT mv2.meter_id, mv2.business_partner_number, mv2.connection_contract_number, max(meter_reading_time) last_read_time FROM app.meter_readings_v2 mr2 JOIN app.meters_v2 mv2 ON mv2.meter_id = mr2.meter_id AND mv2.installation = mr2.installation AND mv2.register = mr2.register AND mv2.isactive = 'Yes' AND district IN ('CA0520', 'CA0560') AND meter_reading_reason = '01' AND end_point_type_1 = '20' GROUP BY mv2.meter_id, mv2.business_partner_number, mv2.connection_contract_number) mr2 ON mr2.meter_id = trim(leading '0' FROM mar.equipmentnumber) AND mr2.business_partner_number = mar.businesspartnernumber AND mr2.connection_contract_number = mar.contractaccount JOIN ( SELECT mv2.meter_id, mv2.register, mv2.business_partner_number, mv2.connection_contract_number, sum(consumption_gl) total_consumption, round(avg(consumption_gl):: numeric,2) avg_consumption, round(stddev_pop(consumption_gl):: numeric,2) std_dev_consumption, round((avg(consumption_gl)+2.5*stddev_pop(consumption_gl))::numeric,2) high_usage_limit, extract( day FROM max(meter_reading_time) - min(meter_reading_time)) total_days, sum(consumption_gl)/extract( day FROM max(meter_reading_time) - min(meter_reading_time)) per_day_consumption, min(meter_reading_time) start_date, max(meter_reading_time) end_date, mnr.next_read_date FROM app.meter_readings_v2 mr2 JOIN app.meters_v2 mv2 ON mv2.meter_id = mr2.meter_id AND mv2.installation = mr2.installation AND mv2.register = mr2.register AND mv2.isactive = 'Yes' AND district IN ('CA0520', 'CA0560') AND meter_reading_reason = '01' AND end_point_type_1 = '20' AND meter_reading_time > CURRENT_TIMESTAMP - interval '15 month' JOIN app.meter_next_read mnr ON mnr.meter_reading_unit = mr2.meter_reading_unit GROUP BY mv2.meter_id, mv2.register, mv2.business_partner_number, mv2.connection_contract_number, mnr.next_read_date) ami_calc ON ami_calc.meter_id = trim(leading '0' FROM mar.equipmentnumber) AND ami_calc.business_partner_number = mar.businesspartnernumber AND ami_calc.connection_contract_number = mar.contractaccount WHERE mar.read_interval_type = 'DAILY' AND mar.reading_datetime > mr2.last_read_time GROUP BY mar.businesspartnernumber, mar.contractaccount, mar.equipmentnumber, mr2.last_read_time, ami_calc.high_usage_limit HAVING ami_calc.high_usage_limit < sum(mar.consumption) AND sum(mar.consumption) > 3000";
    logger.debug(BasicFormatterImpl.format(highUsageSQL));

    debugQuery(highUsageSQL);
    ResultSet rs2 = pgConn.createStatement().executeQuery(highUsageSQL);
    System.out.println("retrieved data");
    String token = getSecureAuthToken();

    while (rs2.next()) {
      String businessPartner = rs2.getString(1);
      String contractAccount = rs2.getString(2);
      String equipmentNumber = rs2.getString(3);
      Timestamp lastReadTime = rs2.getTimestamp(4);
      Double currentUsage = Double.valueOf(rs2.getDouble(5));
      Double highUsageLimit = Double.valueOf(rs2.getDouble(6));
      System.out.println(businessPartner + "," + contractAccount + "," + equipmentNumber + "," + lastReadTime + "," + currentUsage + "," + highUsageLimit);
      String apiUrl = getConfigValue(ApplicationConfig.APP_CONFIG_HIGHUSAGEALERT_ENDPOINT_URL);
      callHighUsageRESTService(pgConn, apiUrl, AccionPayloadAmi.build(businessPartner, contractAccount), token, equipmentNumber, lastReadTime, currentUsage, highUsageLimit);
    }
  }

  private static void updateHourlyData(Connection hiveConn, Connection pgConn) throws SQLException {
    String hourlyDaysThreshold = getConfigValue(ApplicationConfig.APP_CONFIG_TRIGGER_HOURLY_DAYS_MINUS);

    logger.info("hourlyDaysThreshold from config => " + hourlyDaysThreshold);

    if (!hourlyDaysThreshold.startsWith("-")) {
      throw new RuntimeException("Can not work with the non negative -> actual" + hourlyDaysThreshold);
    }

    String aclaraSourceExternalSchemaName = getConfigValue(ApplicationConfig.AMI_SCHEMA_SOURCE_ACLARA_READINGS);

    String hourlySQL = "With tmp as  (select distinct meter_id, transponder_id, transponder_port, cast(customer_id AS String) as functionallocation, reading_value, unit_of_measure, reading_datetime, timezone, battery_voltage,            round(reading_value - lag(reading_value, 1) OVER (partition by  meter_id ORDER BY reading_datetime),2) consumption,            unix_timestamp(reading_datetime)- unix_timestamp(lag(reading_datetime, 1) OVER (partition by  meter_id ORDER BY reading_datetime)) read_interval,           ingest_watermark from " + 
      aclaraSourceExternalSchemaName + ".aclara_readings " + 
      "        where reading_datetime between date_add(current_date," + hourlyDaysThreshold + ") and date_add(current_date,1) " + 
      "          ) " + 
      "        Select distinct 'HOURLY" + intervalSuffix + "' read_interval_type, " + 
      "               tmp.meter_id as headend_meter_id, " + 
      "               tmp.functionallocation, " + 
      "               tmp.reading_datetime, " + 
      "               tmp.timezone, " + 
      "               tmp.reading_value, " + 
      "               tmp.unit_of_measure, " + 
      "               tmp.consumption, " + 
      "               tmp.read_interval, " + 
      "               imd.equipmentnumber, " + 
      "               imd.installation, " + 
      "               imd.register, " + 
      "               imd.logicalregisternumber, " + 
      "               cmd.businesspartnernumber, " + 
      "               cmd.contractaccount, " + 
      "               cmd.utilitiescontract, " + 
      "               cmd.regionalstructuregrouping  " + 
      "        from tmp  " + 
      "        Inner Join awinternal.locationmasterdata lmd on tmp.functionallocation = lmd.functionallocation  " + 
      "        inner join awinternal.installedmeterdetails imd on imd.devicelocation = lmd.functionallocation  " + 
      "               and current_date between imd.devicevaliditystartdate and imd.devicevalidityenddate " + 
      "        inner join cloudseer.mv2_temp  cmd on  cmd.equipmentnumber =imd.equipmentnumber " + 
      "              and current_date between cmd.devicevaliditystartdate and cmd.devicevalidityenddate " + 
      "              and current_date between cmd.utilitiesmoveindate  and cmd.utilitiesmoveoutdate " + 
      "              and imd.register = cmd.register " + 
      "              and cmd.regionalstructuregrouping  in (" + getCountiesListSQLString() + ") " + 
      "        order by headend_meter_id, reading_datetime , imd.register ";

    debugQuery(hourlySQL);
    ResultSet rs1 = hiveConn.createStatement().executeQuery(hourlySQL);
    updateAMIData("HOURLY" + intervalSuffix, pgConn, rs1);
    rs1.close();
  }

  private static void updateHourlyDataWV(Connection hiveConn, Connection pgConn) throws SQLException {
	    String hourlyDaysThreshold = getConfigValue(ApplicationConfig.APP_CONFIG_TRIGGER_HOURLY_DAYS_MINUS);

	    logger.info("hourlyDaysThreshold from config => " + hourlyDaysThreshold);

	    if (!hourlyDaysThreshold.startsWith("-")) {
	      throw new RuntimeException("Can not work with the non negative -> actual" + hourlyDaysThreshold);
	    }

	    //String aclaraSourceExternalSchemaName = getConfigValue(ApplicationConfig.AMI_SCHEMA_SOURCE_ACLARA_READINGS);

	    String hourlySQL = "WITH tmp AS (SELECT DISTINCT meter_id, miu_serial_number AS transponder_id, '1' AS transponder_port, Cast(account_id AS STRING) AS utilities_premise, reading AS reading_value, '' AS unit_of_measure, read_date_time AS reading_datetime, 'GMT' AS timezone, '' AS battery_voltage, Round(reading - Lag(reading, 1) OVER ( partition BY meter_id ORDER BY read_date_time), 2 ) consumption , Unix_timestamp(read_date_time) - Unix_timestamp(Lag(read_date_time, 1) OVER ( partition BY meter_id ORDER BY read_date_time) ) read_interval, ingest_watermark FROM awexternal.ami_datamatic_readings WHERE read_date_time BETWEEN Date_add(CURRENT_DATE, -2) AND Date_add(CURRENT_DATE, 1)) SELECT DISTINCT 'HOURLY' read_interval_type, tmp.meter_id AS headend_meter_id, tmp.utilities_premise, tmp.reading_datetime, tmp.timezone, tmp.reading_value, tmp.unit_of_measure, tmp.consumption, tmp.read_interval, imd.equipmentnumber, imd.installation, imd.register, imd.logicalregisternumber, cmd.businesspartnernumber, cmd.contractaccount, cmd.utilitiescontract, cmd.regionalstructuregrouping, cmd.devicelocation FROM tmp INNER JOIN awinternal.utilitiesinstallation ui ON tmp.utilities_premise = ui.utilitiespremise AND ui.division <> 'SW' INNER JOIN awinternal.installedmeterdetails imd ON ui.utilitiesinstallation = imd.installation AND CURRENT_DATE BETWEEN imd.devicevaliditystartdate AND imd.devicevalidityenddate AND CURRENT_DATE BETWEEN imd.registervaliditystartdate AND imd.registervalidityenddate INNER JOIN cloudseer.mv2_temp cmd ON cmd.equipmentnumber = imd.equipmentnumber AND CURRENT_DATE BETWEEN cmd.devicevaliditystartdate AND cmd.devicevalidityenddate AND CURRENT_DATE BETWEEN cmd.utilitiesmoveindate AND cmd.utilitiesmoveoutdate AND imd.register = cmd.register ORDER BY headend_meter_id, reading_datetime, imd.register";
	    debugQuery(hourlySQL);
	    ResultSet rs1 = hiveConn.createStatement().executeQuery(hourlySQL);
	    updateAMIDataWV("HOURLY" + intervalSuffix, pgConn, rs1);
	    rs1.close();
	  }

  
  private static void updateDailyData(Connection hiveConn, Connection pgConn) throws SQLException {
    String dailyDaysThreshold = getConfigValue(ApplicationConfig.APP_CONFIG_TRIGGER_DAILY_DAYS_MINUS);

    logger.info("dailyDaysThreshold from config => " + dailyDaysThreshold);

    if (!dailyDaysThreshold.startsWith("-")) {
      throw new RuntimeException("Can not work with the non negative -> actual" + dailyDaysThreshold);
    }

    String aclaraSourceExternalSchemaName = getConfigValue(ApplicationConfig.AMI_SCHEMA_SOURCE_ACLARA_READINGS);

    String sql = "With tmp as  (select distinct ar.meter_id, transponder_id, transponder_port, cast(customer_id AS String) as functionallocation,               reading_value, unit_of_measure, ar.reading_datetime, timezone, battery_voltage, ingest_watermark    from " + 
      aclaraSourceExternalSchemaName + ".aclara_readings ar " + 
      "  join ( " + 
      "        select meter_id, max(reading_datetime) reading_datetime, " + 
      "        concat(month(reading_datetime),'-',day(reading_datetime)) meterreadingday " + 
      "        from " + aclaraSourceExternalSchemaName + ".aclara_readings  " + 
      "      where reading_datetime between date_add(current_date," + dailyDaysThreshold + ") and current_date " + 
      "        group by meter_id, concat(month(reading_datetime),'-',day(reading_datetime)) " + 
      "        ) last_row " + 
      "  on last_row.meter_id = ar.meter_id and last_row.reading_datetime = ar.reading_datetime " + 
      ") " + 
      "Select distinct 'DAILY" + intervalSuffix + "' read_interval_type, " + 
      "       tmp.meter_id as headend_meter_id, " + 
      "       tmp.functionallocation, " + 
      "       tmp.reading_datetime, " + 
      "       tmp.timezone, " + 
      "       tmp.reading_value, " + 
      "       tmp.unit_of_measure, " + 
      "       round(reading_value - lag(reading_value, 1) OVER (partition by  meter_id ORDER BY reading_datetime),2) consumption, " + 
      "       unix_timestamp(reading_datetime)- unix_timestamp(lag(reading_datetime, 1) OVER (partition by  meter_id ORDER BY reading_datetime))  read_interval, " + 
      "       imd.equipmentnumber, " + 
      "       imd.installation, " + 
      "       imd.register, " + 
      "       imd.logicalregisternumber, " + 
      "       cmd.businesspartnernumber, " + 
      "       cmd.contractaccount, " + 
      "       cmd.utilitiescontract, " + 
      "       cmd.regionalstructuregrouping " + 
      "from tmp " + 
      "Inner Join awinternal.locationmasterdata lmd on tmp.functionallocation = lmd.functionallocation  " + 
      "inner join awinternal.installedmeterdetails imd on imd.devicelocation = lmd.functionallocation  " + 
      "       and current_date between imd.devicevaliditystartdate and imd.devicevalidityenddate " + 
      "inner join cloudseer.mv2_temp cmd on  cmd.equipmentnumber =imd.equipmentnumber " + 
      "      and current_date between cmd.devicevaliditystartdate and cmd.devicevalidityenddate " + 
      "      and current_date between cmd.utilitiesmoveindate and cmd.utilitiesmoveoutdate " + 
      "      and imd.register = cmd.register " + 
      "      and cmd.regionalstructuregrouping in (" + getCountiesListSQLString() + ") " + 
      "order by headend_meter_id, reading_datetime , imd.register ";

    debugQuery(sql);
    ResultSet rs = hiveConn.createStatement().executeQuery(sql);

    updateAMIData("DAILY" + intervalSuffix, pgConn, rs);
    rs.close();
  }

  
  private static void updateDailyDataWV(Connection hiveConn, Connection pgConn) throws SQLException {
	    String dailyDaysThreshold = getConfigValue(ApplicationConfig.APP_CONFIG_TRIGGER_DAILY_DAYS_MINUS);

	    logger.info("dailyDaysThreshold from config => " + dailyDaysThreshold);

	    if (!dailyDaysThreshold.startsWith("-")) {
	      throw new RuntimeException("Can not work with the non negative -> actual" + dailyDaysThreshold);
	    }

	    //String aclaraSourceExternalSchemaName = getConfigValue(ApplicationConfig.AMI_SCHEMA_SOURCE_ACLARA_READINGS);

	    String sql = "WITH tmp AS (SELECT DISTINCT ar.meter_id, ar.miu_serial_number AS transponder_id, '1' AS transponder_port, Cast(account_id AS STRING) AS utilities_premise, reading AS reading_value, '' AS unit_of_measure, ar.read_date_time AS reading_datetime, 'GMT' AS timezone, '' AS battery_voltage, ingest_watermark FROM awexternal.ami_datamatic_readings ar JOIN (SELECT meter_id, Max(read_date_time) reading_datetime, Concat(Year(read_date_time), '-', Month( read_date_time), '-', Day(read_date_time)) meterreadingday FROM awexternal.ami_datamatic_readings WHERE read_date_time BETWEEN Date_add(CURRENT_DATE, -62 ) AND CURRENT_DATE GROUP BY meter_id, Concat(Year(read_date_time), '-', Month( read_date_time), '-', Day(read_date_time))) last_row ON last_row.meter_id = ar.meter_id AND last_row.reading_datetime = ar.read_date_time) SELECT DISTINCT 'DAILY' read_interval_type, tmp.meter_id AS headend_meter_id, tmp.utilities_premise, tmp.reading_datetime, tmp.timezone, tmp.reading_value, tmp.unit_of_measure, Round(reading_value - Lag(reading_value, 1) OVER ( partition BY meter_id ORDER BY reading_datetime), 2) AS consumption, Unix_timestamp(reading_datetime) - Unix_timestamp(Lag(reading_datetime, 1) OVER ( partition BY meter_id ORDER BY reading_datetime) ) AS read_interval, imd.equipmentnumber, imd.installation, imd.register, imd.logicalregisternumber, cmd.businesspartnernumber, cmd.contractaccount, cmd.utilitiescontract, cmd.regionalstructuregrouping, cmd.devicelocation FROM tmp INNER JOIN awinternal.utilitiesinstallation ui ON tmp.utilities_premise = ui.utilitiespremise AND ui.division <> 'SW' INNER JOIN awinternal.installedmeterdetails imd ON ui.utilitiesinstallation = imd.installation AND CURRENT_DATE BETWEEN imd.devicevaliditystartdate AND imd.devicevalidityenddate AND CURRENT_DATE BETWEEN imd.registervaliditystartdate AND imd.registervalidityenddate INNER JOIN cloudseer.mv2_temp cmd ON cmd.equipmentnumber = imd.equipmentnumber AND CURRENT_DATE BETWEEN cmd.devicevaliditystartdate AND cmd.devicevalidityenddate AND CURRENT_DATE BETWEEN cmd.utilitiesmoveindate AND cmd.utilitiesmoveoutdate AND imd.register = cmd.register ORDER BY headend_meter_id, reading_datetime, imd.register";

	    //debugQuery(sql);
	    ResultSet rs = hiveConn.createStatement().executeQuery(sql);

	    updateAMIDataWV("DAILY" + intervalSuffix, pgConn, rs);
	    rs.close();
	  }

  
  private static void debugQuery(String sql) {
    if (IS_LOG_QUERY.booleanValue()) {
      logger.info("QUERY => " + sql);
      logger.warn("FormattedQuery" + BasicFormatterImpl.format(sql));
    }
  }

  private static void updateAMIData(String readIntervalType, Connection pgConn, ResultSet sourceResultSet) throws SQLException {
    int count = 0;
    if (sourceResultSet.next())
    {
      //String deleteSQL = "delete from app.meter_ami_reads where read_interval_type = '" + readIntervalType + "'";
      //debugQuery(deleteSQL);

      //pgConn.createStatement().executeUpdate(deleteSQL);

      String insertSQL = "INSERT INTO app.meter_ami_reads(             read_interval_type, headend_meter_id, functionallocation, reading_datetime,              timezone, reading_value, unit_of_measure, consumption, read_interval,              equipmentnumber, installation, register, logicalregisternumber,              businesspartnernumber, contractaccount, contract, district)     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      debugQuery(insertSQL);
      PreparedStatement pstmt = pgConn.prepareStatement(insertSQL);
      do
      {
        pstmt.setString(1, sourceResultSet.getString(1));
        pstmt.setString(2, sourceResultSet.getString(2));
        pstmt.setString(3, sourceResultSet.getString(3));
        pstmt.setTimestamp(4, sourceResultSet.getTimestamp(4));
        pstmt.setString(5, sourceResultSet.getString(5));
        pstmt.setDouble(6, sourceResultSet.getDouble(6));
        pstmt.setString(7, sourceResultSet.getString(7));
        pstmt.setDouble(8, sourceResultSet.getDouble(8));
        pstmt.setInt(9, sourceResultSet.getInt(9));
        pstmt.setString(10, sourceResultSet.getString(10));
        pstmt.setString(11, String.valueOf(sourceResultSet.getLong(11)));
        pstmt.setString(12, sourceResultSet.getString(12));
        pstmt.setString(13, sourceResultSet.getString(13));
        pstmt.setString(14, sourceResultSet.getString(14));
        pstmt.setString(15, String.valueOf(sourceResultSet.getLong(15)));
        pstmt.setString(16, String.valueOf(sourceResultSet.getLong(16)));
        pstmt.setString(17, sourceResultSet.getString(17));
        //pstmt.setString(18, sourceResultSet.getString(18));
        pstmt.addBatch();
        count++;
      }while (sourceResultSet.next());
      pstmt.executeBatch();
    } else {
      System.out.println("Skipping. ResultSet was empty - at " + new Date() + " \treadIntervalType=" + readIntervalType);
    }
    System.out.println("Inserted " + count + " rows");
  }

  private static void updateAMIDataWV(String readIntervalType, Connection pgConn, ResultSet sourceResultSet) throws SQLException {
	    int count = 0;
	    if (sourceResultSet.next())
	    {
	      String deleteSQL = "delete from app.meter_ami_reads where read_interval_type = '" + readIntervalType + "'";
	      debugQuery(deleteSQL);

	      pgConn.createStatement().executeUpdate(deleteSQL);

	      String insertSQL = "INSERT INTO app.meter_ami_reads(read_interval_type, headend_meter_id, utilities_premise, reading_datetime,              timezone, reading_value, unit_of_measure, consumption, read_interval,              equipmentnumber, installation, register, logicalregisternumber,              businesspartnernumber, contractaccount, contract, district, functionallocation)     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ";
	      debugQuery(insertSQL);
	      PreparedStatement pstmt = pgConn.prepareStatement(insertSQL);
	      do
	      {
	        pstmt.setString(1, sourceResultSet.getString(1));
	        pstmt.setString(2, sourceResultSet.getString(2));
	        pstmt.setString(3, sourceResultSet.getString(3));
	        pstmt.setTimestamp(4, sourceResultSet.getTimestamp(4));
	        pstmt.setString(5, sourceResultSet.getString(5));
	        pstmt.setDouble(6, sourceResultSet.getDouble(6));
	        pstmt.setString(7, sourceResultSet.getString(7));
	        pstmt.setDouble(8, sourceResultSet.getDouble(8));
	        pstmt.setInt(9, sourceResultSet.getInt(9));
	        pstmt.setString(10, sourceResultSet.getString(10));
	        pstmt.setString(11, String.valueOf(sourceResultSet.getLong(11)));
	        pstmt.setString(12, sourceResultSet.getString(12));
	        pstmt.setString(13, sourceResultSet.getString(13));
	        pstmt.setString(14, sourceResultSet.getString(14));
	        pstmt.setString(15, String.valueOf(sourceResultSet.getLong(15)));
	        pstmt.setString(16, String.valueOf(sourceResultSet.getLong(16)));
	        pstmt.setString(17, sourceResultSet.getString(17));
	        pstmt.setString(18, sourceResultSet.getString(18));
	        pstmt.addBatch();
	        count++;
	      }while (sourceResultSet.next());
	      pstmt.executeBatch();
	    } else {
	    	logger.info("Skipping. ResultSet was empty - at " + new Date() + " \treadIntervalType=" + readIntervalType);
	    }
	    logger.info("Inserted " + count + " rows "+getTime());
	  }

  
  /*private static void updateUsagePrediction(Connection pgConn, Double zScore) throws SQLException
  {
    String usagePredictionMonthsThreshold = getConfigValue(ApplicationConfig.APP_CONFIG_USAGE_PREDICTION_NUMBER_OF_PAST_MONTHS);

    logger.info("usagePredictionMonthsThreshold from config => " + usagePredictionMonthsThreshold);

    String insertSQL = "INSERT INTO app.meter_ami_projected_consumption(             business_partner_number, premise_id, connection_contract_number,              meter_id, service_period_start, service_period_end, curr_read_consumption,              curr_read_date, per_day_consumption, days_to_next_read, projected_consumption)     VALUES (?, ?, ?,              ?, ?, ?, ?,              ?, ?, ?, ?) ";

    String readDateSQL = "SELECT   mar.businesspartnernumber business_partner_number,           cc.premise_id,           mar.contractaccount                        connection_contract_number,           trim(leading '0' FROM mar.equipmentnumber) meter_id,           mr2.last_read_time::date                   service_period_start,           ami_calc.next_read_date                    service_period_end,          sum(mar.consumption)                       curr_read_consumption,           max(mar.reading_datetime)::date            curr_read_date,           round(ami_calc.per_day_consumption::numeric,2),            extract('day' FROM ami_calc.next_read_date - max(mar.reading_datetime))                                                                           days_to_next_read,          sum(mar.consumption) + round((extract('day' FROM ami_calc.next_read_date - max(mar.reading_datetime)) * ami_calc.per_day_consumption)::numeric,2) projected_consumption FROM     app.meter_ami_reads mar  JOIN          (                    SELECT   mv2.meter_id,                             mv2.business_partner_number,                             mv2.connection_contract_number,                             max(meter_reading_time) last_read_time                    FROM     app.meter_readings_v2 mr2                    JOIN     app.meters_v2 mv2                    ON       mv2.meter_id = mr2.meter_id                    AND      mv2.isactive = 'Yes'                    AND      district IN (" + 
      getCountiesListSQLString() + ")  " + 
      "                  AND      meter_reading_reason = '01'  " + 
      "                  AND      end_point_type_1 = '20' " + 
      "                  GROUP BY mv2.meter_id,  " + 
      "                           mv2.business_partner_number,  " + 
      "                           mv2.connection_contract_number " + 
      "\t\t) mr2  " + 
      "\t\tON       mr2.meter_id = trim(leading '0' FROM mar.equipmentnumber)  " + 
      "\t\tAND      mr2.business_partner_number = mar.businesspartnernumber  " + 
      "\t\tAND      mr2.connection_contract_number = mar.contractaccount  " + 
      "JOIN  " + 
      "        (  " + 
      "                  SELECT   mv2.meter_id,  " + 
      "                           mv2.register,  " + 
      "                           mv2.business_partner_number,  " + 
      "                           mv2.connection_contract_number,  " + 
      "                           sum(consumption_gl)                                                                      total_consumption, " + 
      "                           round(avg(consumption_gl)::                                 numeric,2)                   avg_consumption, " + 
      "                           round(stddev_pop(consumption_gl)::                          numeric,2)                   std_dev_consumption, " + 
      "                           round((avg(consumption_gl)+" + zScore + "*stddev_pop(consumption_gl))::numeric,2)                   high_usage_limit, " + 
      "                           extract( day FROM max(meter_reading_time) - min(meter_reading_time))                     total_days, " + 
      "                           sum(consumption_gl)/extract( day FROM max(meter_reading_time) - min(meter_reading_time)) per_day_consumption, " + 
      "                           min(meter_reading_time)                                                                  start_date, " + 
      "                           max(meter_reading_time)                                                                  end_date, " + 
      "                           mnr.next_read_date  " + 
      "                  FROM     app.meter_readings_v2 mr2  " + 
      "                  JOIN     app.meters_v2 mv2  " + 
      "                  ON       mv2.meter_id = mr2.meter_id  " + 
      "                  AND      mv2.isactive = 'Yes'  " + 
      "                  AND      district IN (" + getCountiesListSQLString() + ")  " + 
      "                  AND      meter_reading_reason = '01'  " + 
      "                  AND      end_point_type_1 = '20'  " + 
      "                  AND      meter_reading_time> CURRENT_TIMESTAMP - interval '" + usagePredictionMonthsThreshold + " month'  " + 
      "                  JOIN     app.meter_next_read mnr  " + 
      "                  ON       mnr.meter_reading_unit = mr2.meter_reading_unit  " + 
      "                  GROUP BY mv2.meter_id,  " + 
      "                           mv2.register,  " + 
      "                           mv2.business_partner_number,  " + 
      "                           mv2.connection_contract_number,  " + 
      "                           mnr.next_read_date " + 
      "\t\t) ami_calc  " + 
      "\t\tON       ami_calc.meter_id = trim(leading '0' FROM mar.equipmentnumber)  " + 
      "\t\tAND      ami_calc.business_partner_number = mar.businesspartnernumber  " + 
      "\t\tAND      ami_calc.connection_contract_number = mar.contractaccount  " + 
      "JOIN    app.connection_contracts cc  " + 
      "\t\tON       mar.businesspartnernumber = cc.business_partner_number  " + 
      "\t\tAND      mar.contractaccount = cc.connection_contract_number " + 
      "WHERE    mar.read_interval_type = 'DAILY" + intervalSuffix + "'  " + 
      "AND      mar.reading_datetime> mr2.last_read_time  " + 
      "GROUP BY mar.businesspartnernumber,  " + 
      "         cc.premise_id,  " + 
      "         mar.contractaccount,  " + 
      "         mar.equipmentnumber,  " + 
      "         mr2.last_read_time,  " + 
      "         ami_calc.per_day_consumption,  " + 
      "         ami_calc.next_read_date";

    debugQuery(readDateSQL);
    ResultSet sourceResultSet = pgConn.createStatement().executeQuery(readDateSQL);

    String deleteSQL = "delete from app.meter_ami_projected_consumption";

    debugQuery(deleteSQL);
    pgConn.createStatement().executeUpdate(deleteSQL);

    debugQuery(insertSQL);
    PreparedStatement pstmt = pgConn.prepareStatement(insertSQL);

    int count = 0;
    while (sourceResultSet.next()) {
      pstmt.setString(1, sourceResultSet.getString(1));
      pstmt.setString(2, sourceResultSet.getString(2));
      pstmt.setString(3, sourceResultSet.getString(3));
      pstmt.setString(4, sourceResultSet.getString(4));
      pstmt.setDate(5, sourceResultSet.getDate(5));
      pstmt.setDate(6, sourceResultSet.getDate(6));
      pstmt.setBigDecimal(7, sourceResultSet.getBigDecimal(7));
      pstmt.setDate(8, sourceResultSet.getDate(8));
      pstmt.setBigDecimal(9, sourceResultSet.getBigDecimal(9));
      pstmt.setInt(10, sourceResultSet.getInt(10));
      pstmt.setBigDecimal(11, sourceResultSet.getBigDecimal(11));
      pstmt.addBatch();
      count++;
    }
    pstmt.executeBatch();
    System.out.println("meter_ami_projected_consumption: Inserted " + count + " rows");

    sourceResultSet.close();
  }*/
  
  private static void updateUsagePrediction(Connection pgConn, Double zScore) throws SQLException
  {
    String usagePredictionMonthsThreshold = getConfigValue(ApplicationConfig.APP_CONFIG_USAGE_PREDICTION_NUMBER_OF_PAST_MONTHS);

    logger.info("usagePredictionMonthsThreshold from config => " + usagePredictionMonthsThreshold);

    String insertSQL = "INSERT INTO app.meter_ami_projected_consumption(             business_partner_number, premise_id, connection_contract_number,              meter_id, service_period_start, service_period_end, curr_read_consumption,              curr_read_date, per_day_consumption, days_to_next_read, projected_consumption)     VALUES (?, ?, ?,              ?, ?, ?, ?,              ?, ?, ?, ?) ";

    String readDateSQL = "SELECT mar.businesspartnernumber business_partner_number, cc.premise_id, Cast (mar.contractaccount AS VARCHAR) connection_contract_number, trim(leading '0' FROM mar.equipmentnumber) meter_id, mr2.last_read_time::date service_period_start, ami_calc.next_read_date service_period_end, sum(mar.consumption) curr_read_consumption, max(mar.reading_datetime)::date curr_read_date, round(ami_calc.per_day_consumption::numeric,2), extract('day' FROM ami_calc.next_read_date - max(mar.reading_datetime)) days_to_next_read, sum(mar.consumption) + round((extract('day' FROM ami_calc.next_read_date - max(mar.reading_datetime)) * ami_calc.per_day_consumption)::numeric,2) projected_consumption FROM app.meter_ami_reads mar JOIN ( SELECT mv2.meter_id, mv2.business_partner_number, mv2.connection_contract_number, max(meter_reading_time) last_read_time FROM app.meter_readings_v2 mr2 JOIN app.meters_v2 mv2 ON mv2.meter_id = mr2.meter_id AND mv2.isactive = 'Yes' AND meter_reading_reason = '01' JOIN app.meter_endpoint_type met ON mv2.end_point_type_1 = met.id AND met.endpoint_group = 'AMI' GROUP BY mv2.meter_id, mv2.business_partner_number, mv2.connection_contract_number ) mr2 ON mr2.meter_id = trim(leading '0' FROM mar.equipmentnumber) AND mr2.business_partner_number = mar.businesspartnernumber AND mr2.connection_contract_number = cast (mar.contractaccount AS varchar) JOIN ( SELECT mv2.meter_id, mv2.register, mv2.business_partner_number, mv2.connection_contract_number, sum(consumption_gl) total_consumption, round(avg(consumption_gl):: numeric,2) avg_consumption, round(stddev_pop(consumption_gl):: numeric,2) std_dev_consumption, round((avg(consumption_gl)+2.5*stddev_pop(consumption_gl))::numeric,2) high_usage_limit, extract( day FROM max(meter_reading_time) - min(meter_reading_time)) total_days, case when extract( day FROM max(meter_reading_time) - min(meter_reading_time)) > 0 then sum(consumption_gl)/extract( day FROM max(meter_reading_time) - min(meter_reading_time)) else 0 end per_day_consumption, min(meter_reading_time) start_date, max(meter_reading_time) end_date, mnr.next_read_date FROM app.meter_readings_v2 mr2 JOIN app.meters_v2 mv2 ON mv2.meter_id = mr2.meter_id AND mv2.isactive = 'Yes' AND meter_reading_reason = '01' AND meter_reading_time> CURRENT_TIMESTAMP - interval '15 month' JOIN app.meter_endpoint_type met ON mv2.end_point_type_1 = met.id AND met.endpoint_group = 'AMI' JOIN app.meter_next_read mnr ON mnr.meter_reading_unit = mr2.meter_reading_unit GROUP BY mv2.meter_id, mv2.register, mv2.business_partner_number, mv2.connection_contract_number, next_read_date ) ami_calc ON ami_calc.meter_id = trim(leading '0' FROM mar.equipmentnumber) AND ami_calc.business_partner_number = mar.businesspartnernumber AND ami_calc.connection_contract_number = cast (mar.contractaccount AS varchar) JOIN app.connection_contracts cc ON mar.businesspartnernumber = cc.business_partner_number AND cast (mar.contractaccount AS varchar) = cc.connection_contract_number WHERE mar.reading_datetime> mr2.last_read_time and mar.read_interval_type = 'DAILY' GROUP BY mar.businesspartnernumber, cc.premise_id, mar.contractaccount, mar.equipmentnumber, mr2.last_read_time, ami_calc.per_day_consumption, ami_calc.next_read_date";

    debugQuery(readDateSQL);
    ResultSet sourceResultSet = pgConn.createStatement().executeQuery(readDateSQL);

    String deleteSQL = "delete from app.meter_ami_projected_consumption";

    debugQuery(deleteSQL);
    pgConn.createStatement().executeUpdate(deleteSQL);

    debugQuery(insertSQL);
    PreparedStatement pstmt = pgConn.prepareStatement(insertSQL);

    int count = 0;
    while (sourceResultSet.next()) {
      pstmt.setString(1, sourceResultSet.getString(1));
      pstmt.setString(2, sourceResultSet.getString(2));
      pstmt.setString(3, sourceResultSet.getString(3));
      pstmt.setString(4, sourceResultSet.getString(4));
      pstmt.setDate(5, sourceResultSet.getDate(5));
      pstmt.setDate(6, sourceResultSet.getDate(6));
      pstmt.setBigDecimal(7, sourceResultSet.getBigDecimal(7));
      pstmt.setDate(8, sourceResultSet.getDate(8));
      pstmt.setBigDecimal(9, sourceResultSet.getBigDecimal(9));
      pstmt.setInt(10, sourceResultSet.getInt(10));
      pstmt.setBigDecimal(11, sourceResultSet.getBigDecimal(11));
      pstmt.addBatch();
      count++;
    }
    pstmt.executeBatch();
    System.out.println("meter_ami_projected_consumption: Inserted " + count + " rows");

    sourceResultSet.close();
  }

  public static Connection zookeeperConnect() throws Exception
  {
    String url = getConfigValue(ApplicationConfig.APP_CONFIG_HIVE_JDBC_URI);
    String principal = getConfigValue(ApplicationConfig.APP_CONFIG_HIVE_KERBEROS_PRINCIPAL);

    String keyTab = null;

    keyTab = getConfigValue(ApplicationConfig.APP_CONFIG_HIVE_KERBEROS_KEYTAB_FILEPATH);
    try
    {
      Configuration conf = new Configuration();
      conf.set("hadoop.security.authentication", "Kerberos");
      UserGroupInformation.setConfiguration(conf);
      UserGroupInformation.loginUserFromKeytab(principal, keyTab);
      Class.forName("org.apache.hive.jdbc.HiveDriver");

      return DriverManager.getConnection(url);
    }
    catch (SQLException e) {
      e.printStackTrace();
      if (e.getNextException() != null) {
        e.getNextException().printStackTrace();
      }
      throw e;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  private static Connection getPostgresConnection(String jdbcUrl, String uid, String pwd) throws SQLException {
    try {
      Class.forName("org.postgresql.Driver");
      Connection connection = null;
      return DriverManager.getConnection(jdbcUrl, uid, pwd);
    }
    catch (ClassNotFoundException e) {
      e.printStackTrace();
    }
    return null;
  }

  /*private static void updateMeterNextRead(Connection hiveConn, Connection pgConn) throws SQLException
  {
    String insertSQL = "INSERT INTO app.meter_next_read(meter_reading_unit, next_read_date)  VALUES (?, ?)";
    String readDateSQL = "select meterreadingunit,min(scheduledmeterreadingdate) next_read_date from awinternal.meterreadingunitschedulerecord  where scheduledmeterreadingdate >= current_date() group by meterreadingunit ";

    debugQuery(readDateSQL);
    ResultSet sourceResultSet = hiveConn.createStatement().executeQuery(readDateSQL);

    String deleteSQL = "delete from app.meter_next_read";
    debugQuery(deleteSQL);
    pgConn.createStatement().executeUpdate(deleteSQL);

    debugQuery(insertSQL);
    PreparedStatement pstmt = pgConn.prepareStatement(insertSQL);
    int count = 0;
    while (sourceResultSet.next()) {
      pstmt.setString(1, sourceResultSet.getString(1));
      pstmt.setDate(2, sourceResultSet.getDate(2));
      pstmt.addBatch();
      count++;
    }

    pstmt.executeBatch();
    System.out.println("updateMeterNextRead: Inserted " + count + " rows");
    sourceResultSet.close();
  }
*/
  
  private static void updateMeterNextRead(Connection hiveConn, Connection pgConn) throws SQLException
  {
    String insertSQL = "INSERT INTO app.meter_next_read(meter_reading_unit, next_read_date)  VALUES (?, ?)";
    String readDateSQL = "select meterreadingunit,min(scheduledmeterreadingdate) from app.meter_mru_schedule_records where scheduledmeterreadingdate >= current_date group by meterreadingunit";

    debugQuery(readDateSQL);
    ResultSet sourceResultSet = pgConn.createStatement().executeQuery(readDateSQL);

    String deleteSQL = "delete from app.meter_next_read";
    debugQuery(deleteSQL);
    pgConn.createStatement().executeUpdate(deleteSQL);

    debugQuery(insertSQL);
    PreparedStatement pstmt = pgConn.prepareStatement(insertSQL);
    int count = 0;
    while (sourceResultSet.next()) {
      pstmt.setString(1, sourceResultSet.getString(1));
      pstmt.setDate(2, sourceResultSet.getDate(2));
      pstmt.addBatch();
      count++;
    }

    pstmt.executeBatch();
    logger.info("updateMeterNextRead: Inserted " + count + " rows "+ getTime());
    sourceResultSet.close();
  }

  
  private static String getSecureAuthToken() throws Exception
  {
    String token = null;
    try
    {
      String secureAuthTokenUrl = getConfigValue(ApplicationConfig.AMI_SECUREAUTH_CONFIG_OAUTH_URL);
      List paramList = new ArrayList();

      paramList.add(new BasicNameValuePair(LoadAMIData.SecureAuthParam.grant_type.name(), getConfigValue(ApplicationConfig.AMI_SECUREAUTH_CONFIG_GRANT_TYPE)));
      paramList.add(new BasicNameValuePair(LoadAMIData.SecureAuthParam.username.name(), getConfigValue(ApplicationConfig.AMI_SECUREAUTH_CONFIG_USERNAME)));
      paramList.add(new BasicNameValuePair(LoadAMIData.SecureAuthParam.password.name(), getConfigValue(ApplicationConfig.AMI_SECUREAUTH_CONFIG_PASSWORD)));
      paramList.add(new BasicNameValuePair(LoadAMIData.SecureAuthParam.client_id.name(), getConfigValue(ApplicationConfig.AMI_SECUREAUTH_CONFIG_CLIENT_ID)));
      paramList.add(new BasicNameValuePair(LoadAMIData.SecureAuthParam.client_secret.name(), getConfigValue(ApplicationConfig.AMI_SECUREAUTH_CONFIG_CLIENT_SECRET)));
      paramList.add(new BasicNameValuePair(LoadAMIData.SecureAuthParam.scope.name(), getConfigValue(ApplicationConfig.AMI_SECUREAUTH_CONFIG_SCOPE)));

      client = HttpClients.custom().setSslcontext(new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy()
      {
        public boolean isTrusted(X509Certificate[] arg0, String arg1)
          throws CertificateException
        {
          return true;
        }
      }).build()).setDefaultHeaders(Lists.newArrayList(new BasicHeader[] { 
        new BasicHeader("Accept", "application/json") })).build();

      HttpUriRequest request = RequestBuilder.post().setUri(secureAuthTokenUrl)
        .setHeader("Content-Type", "application/x-www-form-urlencoded")
        .setEntity(new UrlEncodedFormEntity(paramList))
        .build();
      HttpResponse response = client.execute(request);

      logger.info("response code = " + response.getStatusLine().getStatusCode());
      logger.info(response);

      String responseJSONStr = EntityUtils.toString(response.getEntity());
      token = new JsonParser().parse(responseJSONStr).getAsJsonObject().get("access_token").getAsString();
      logger.debug(responseJSONStr);
    } catch (Exception e) {
      logger.error(e, e.getCause());
      throw e;
    }
    return token;
  }

  private static void callHighUsageRESTService(Connection pgConn, String urlPath, AccionPayloadAmi payload, String token, String equipmentNumber, Timestamp lastReadTime, Double currentUsage, Double highUsageLimit) throws Exception {
    HttpResponse response = callRESTServiceInternal(pgConn, urlPath, payload, token);

    String responseJSON = EntityUtils.toString(response.getEntity());
    logger.info(responseJSON);
    logger.info("---------------");

    AuditAlertEvent.insertHighUsageAuditRecord(pgConn, StringUtils.substringAfterLast(urlPath, "/"), responseJSON, 
      response.toString(), response.getStatusLine().getReasonPhrase(), payload.toJson(), urlPath, equipmentNumber, lastReadTime, currentUsage, highUsageLimit, payload.getBusinessPartnerNumber(), payload.getContractAccountNumber());
  }

  private static void callLeaksRESTService(Connection pgConn, String urlPath, AccionPayloadAmi payload, String token) throws Exception {
    HttpResponse response = callRESTServiceInternal(pgConn, urlPath, payload, token);

    String responseJSON = EntityUtils.toString(response.getEntity());
    logger.info(responseJSON);
    logger.info("^--------------");

    AuditAlertEvent.insertLeaksAuditRecord(pgConn, StringUtils.substringAfterLast(urlPath, "/"), responseJSON, 
      response.toString(), response.getStatusLine().getReasonPhrase(), payload.toJson(), urlPath, payload.getBusinessPartnerNumber(), payload.getContractAccountNumber());
  }

  private static HttpResponse callRESTServiceInternal(Connection pgConn, String urlPath, AccionPayloadAmi payload, String token) throws Exception
  {
    HttpUriRequest request = RequestBuilder.post().setUri(urlPath)
      .setEntity(new StringEntity(payload.toJson()))
      .addHeader("Authorization", token)
      .setHeader("Content-Type", "application/json; charset=utf-8")
      .build();
    logger.info(urlPath);
    logger.info(payload.toJson());
    logger.info(request);
    logger.info(((HttpEntityEnclosingRequest)request).getEntity());

    HttpResponse response = client.execute(request);
    logger.info("response code = " + response.getStatusLine().getStatusCode());
    logger.info(response);
    return response;
  }

  private static enum SecureAuthParam
  {
    grant_type, client_id, client_secret, scope, username, password;
  }
  
  private static Date getTime() {
	  TimeZone.setDefault(TimeZone.getTimeZone("CTT"));
	  return new Date();
  }
}