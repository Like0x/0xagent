# 0xagent
CobaltStrike 4.0 - 4.5 Patch


Changed from [CSAgent](https://github.com/Twi1ight/CSAgent). review by [dust-life](https://github.com/dust-life).

The key for 4.5 is not available here, Just a loader.

## features

- Check the file hash from CS official Website
- Patch javaagemt detection
- Patch Authorization
- Patch Checksum8

Just that's all.

**Tips**
- Using jdk8 will make the startup time as long as 10-15s
- Versions after using jdk8 will start immediately
- If you want to use the `checksum8` feature, name the profile `c3.profile`.

## Usage
![image](https://user-images.githubusercontent.com/19629138/167308302-f8f89594-73d9-4205-b13c-d188692e9c61.png)

e.g: 4.4 key

Client
```
java -XX:ParallelGCThreads=4 -XX:+AggressiveHeap -XX:+UseParallelGC -Xms512M -Xmx1024M -javaagent:0xagent.jar=5e98194a01c6b48fa582a6a9fcbb92d6 -jar cobaltstrike.jar
```
![image](https://user-images.githubusercontent.com/19629138/167308485-c28a66f9-ba90-43dc-b1eb-70a47f803a39.png)


Teamserver
```
java -XX:ParallelGCThreads=4 -Dcobaltstrike.server_port=59850 -Djavax.net.ssl.keyStore=./xxxx.store -Djavax.net.ssl.keyStorePassword=xxxxxx -server -XX:+AggressiveHeap -XX:+UseParallelGC -javaagent:0xagent.jar=5e98194a01c6b48fa582a6a9fcbb92d6 -classpath ./cobaltstrike.jar server.TeamServer $*
```

