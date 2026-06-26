rule Backdoor_Webshell {
    meta:
        description = "Detects Python webshell or remote command execution patterns"
        author = "Aegis"
    strings:
        $p1 = "eval(request.args" ascii wide
        $p2 = "eval(request.form" ascii wide
        $p3 = "exec(request.args" ascii wide
        $p4 = "exec(request.form" ascii wide
        $p5 = "eval(request.values" ascii wide
        $p6 = "exec(request.values" ascii wide
        $p7 = "subprocess.Popen(request.args" ascii wide
        $p8 = "subprocess.check_output(request.args" ascii wide
    condition:
        any of them
}

rule Obfuscated_Payload {
    meta:
        description = "Detects base64 obfuscation combined with execution"
        author = "Aegis"
    strings:
        $s1 = "base64.b64decode" ascii wide
        $s2 = "exec(" ascii wide
        $s3 = "eval(" ascii wide
    condition:
        $s1 and ($s2 or $s3)
}

rule Suspicious_Shell_Spawn {
    meta:
        description = "Detects shell spawning commands, likely for reverse shells"
        author = "Aegis"
    strings:
        $sh1 = "/bin/sh" ascii wide
        $sh2 = "/bin/bash" ascii wide
        $sh3 = "pty.spawn" ascii wide
        $sh4 = "socket.socket" ascii wide
        $sub1 = "subprocess.Popen" ascii wide
        $sub2 = "subprocess.call" ascii wide
    condition:
        ($sh1 or $sh2) and $sh3 or ($sh4 and ($sub1 or $sub2) and ($sh1 or $sh2))
}
