package com.geeksonsecurity.malwaredemo;

import android.app.ActivityManager;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;


/**
 * Based on http://stackoverflow.com/questions/30619349/android-5-1-1-and-above-getrunningappprocesses-returns-my-application-packag
 */
public class ProcessHelper {

    /** first app user */
    public static final int AID_APP = 10000;

    /** offset for uid ranges for each user */
    public static final int AID_USER = 100000;
    private ActivityManager _activityManager;

    public ProcessHelper(ActivityManager activityManager) {
        _activityManager = activityManager;
    }

    public String getForegroundApp() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            @SuppressWarnings("deprecation") ActivityManager.RunningTaskInfo foregroundTaskInfo = _activityManager.getRunningTasks(1).get(0);
            return foregroundTaskInfo.topActivity.getPackageName();
        } else {
            File[] files = new File("/proc").listFiles();
            int lowestOomScore = Integer.MAX_VALUE;
            String foregroundProcess = null;

            for (File file : files) {
                if (!file.isDirectory()) {
                    continue;
                }

                int pid;
                try {
                    pid = Integer.parseInt(file.getName());
                } catch (NumberFormatException e) {
                    continue;
                }

                try {
                    String cgroup = read(String.format("/proc/%d/cgroup", pid));

                    String[] lines = cgroup.split("\n");

                    if (lines.length != 2) {
                        continue;
                    }

                    String cpuSubsystem = lines[0];
                    String cpuaccctSubsystem = lines[1];

                    if (!cpuaccctSubsystem.endsWith(Integer.toString(pid))) {
                        // not an application process
                        continue;
                    }

                    if (cpuSubsystem.endsWith("bg_non_interactive")) {
                        // background policy
                        continue;
                    }

                    String cmdline = read(String.format("/proc/%d/cmdline", pid));

                    if (cmdline.contains("com.android.systemui")) {
                        continue;
                    }

                    int uid = Integer.parseInt(
                            cpuaccctSubsystem.split(":")[2].split("/")[1].replace("uid_", ""));
                    if (uid >= 1000 && uid <= 1038) {
                        // system process
                        continue;
                    }

                    int appId = uid - AID_APP;
                    int userId = 0;
                    // loop until we get the correct user id.
                    // 100000 is the offset for each user.
                    while (appId > AID_USER) {
                        appId -= AID_USER;
                        userId++;
                    }

                    if (appId < 0) {
                        continue;
                    }

                    // u{user_id}_a{app_id} is used on API 17+ for multiple user account support.
                    // String uidName = String.format("u%d_a%d", userId, appId);

                    File oomScoreAdj = new File(String.format("/proc/%d/oom_score_adj", pid));
                    if (oomScoreAdj.canRead()) {
                        int oomAdj = Integer.parseInt(read(oomScoreAdj.getAbsolutePath()));
                        if (oomAdj != 0) {
                            continue;
                        }
                    }

                    int oomscore = Integer.parseInt(read(String.format("/proc/%d/oom_score", pid)));
                    if (oomscore < lowestOomScore) {
                        lowestOomScore = oomscore;
                        foregroundProcess = cmdline;
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return foregroundProcess;
        }
    }

    private static String read(String path) throws IOException {
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(new FileReader(path));
        output.append(reader.readLine());
        for (String line = reader.readLine(); line != null; line = reader.readLine()) {
            output.append('\n').append(line);
        }
        reader.close();
        return output.toString();
    }
}
