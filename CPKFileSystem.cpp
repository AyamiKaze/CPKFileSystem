// CPKFileSystem.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
// After compress: camellia
#include "Native.h"

#define PACK_NAME "saclet_cn.cpk"
#define KEY_NAME  "saclet_cn.key"
#define HEADER_KEY "绿茶汉化组"

#define MAGIC "CPK\0"
#define VERSION "\x02\x00\x00\x00"
#define WARNING "本补丁由【绿茶汉化组】制作，禁止拆解破解本补丁。"

#define KEY_TOP_KEY 0x11451490

void GenSHA256(byte* Str, DWORD StrLen, char** SHAContent)
{
    SHA256 hash;
    hash.Update((byte*)HEADER_KEY, strlen(HEADER_KEY));
    hash.Update((byte*)Str, StrLen);
    hash.Final((byte*)*SHAContent);
}


#pragma pack (1)
// CPKFile
struct CPKHeader {
    char Magic[4];
    char Version[4];
    char Warning[128];
    DWORD IndexCount;
};
struct CPKIndex {
    char FileName[32];
    DWORD FileSize;
    DWORD CompressFileSize;
    DWORD Offset;
};
// KeyFile
struct KeyHeader {
    char Magic[4]; // "CPK\0"
    DWORD IndexCount;
    char HeaderHash[SHA256::DIGESTSIZE];
};
struct CamelliaKey {
    DWORD KeySize;
    DWORD IvSize;
    BYTE Key[Camellia::DEFAULT_KEYLENGTH];
    BYTE Iv[Camellia::BLOCKSIZE];
};
struct KeyIndex {
    char IndexHash[SHA256::DIGESTSIZE];
    CamelliaKey KeyAfterCompress;
};
#pragma pack ()

int main()
{
    CPKHeader CPK_Header;
    CPKIndex  CPK_Index;
    KeyHeader Key_Header;
    KeyIndex  Key_Index;

    fileSearch("packdata");
    cout << "Count:" << FilePool.size() << endl;

    FILE* cpk = fopen(PACK_NAME, "wb");
    FILE* key = fopen(KEY_NAME, "wb");

    strncpy(CPK_Header.Magic, MAGIC, 4);
    strncpy(Key_Header.Magic, MAGIC, 4);
    strncpy(CPK_Header.Version, VERSION, 4);
    strcpy(CPK_Header.Warning, WARNING);
    CPK_Header.IndexCount = FilePool.size();
    Key_Header.IndexCount = FilePool.size();

    BYTE* CPKHeaderBuff = new BYTE[sizeof(CPKHeader)];
    memmove(CPKHeaderBuff, &CPK_Header, sizeof(CPKHeader));

    char* HeaderHash = new char[SHA256::DIGESTSIZE];
    GenSHA256(CPKHeaderBuff, sizeof(CPKHeader), &HeaderHash);
    memcpy(Key_Header.HeaderHash, HeaderHash, SHA256::DIGESTSIZE);

    ///*
    for (int i = 0; i < sizeof(CPKHeader); i++)
        CPKHeaderBuff[i] ^= Key_Header.HeaderHash[i % SHA256::DIGESTSIZE];
    //*/

    BYTE* KeyHeaderBuff = new BYTE[sizeof(KeyHeader)];
    memmove(KeyHeaderBuff, &Key_Header, sizeof(KeyHeader));

    ///*
    for (int i = 0; i < sizeof(KeyHeader); i++)
        KeyHeaderBuff[i] ^= KEY_TOP_KEY;
    //*/
    fwrite(CPKHeaderBuff, sizeof(CPKHeader), 1, cpk);
    fwrite(KeyHeaderBuff, sizeof(KeyHeader), 1, key);

    DWORD count = 0;
    DWORD pos = 0;
    for (string f : FilePool)
    {
        FILE* fin = fopen(f.c_str(), "rb");
        fseek(fin, 0, SEEK_END);
        DWORD FileSize = ftell(fin);
        fseek(fin, 0, SEEK_SET);
        BYTE* FileBuff = new BYTE[FileSize];
        fread(FileBuff, FileSize, 1, fin);
        fclose(fin);

        cout << "--------------------------------" << endl;
        string fnm = f.substr(f.find_first_of("\\") + 1);
        FileNameToLower(fnm);
        cout << fnm.c_str() << endl;
        cout << "start compress and encrypt" << endl;
        cout << "FileSize:0x" << hex << FileSize << endl;

        ZlibCompressor cmp;
        cmp.Put(FileBuff, FileSize);
        cmp.MessageEnd();
        DWORD CompressSize = cmp.MaxRetrievable();
        BYTE* CompressBuff = new BYTE[CompressSize];
        cmp.Get(CompressBuff, CompressSize);
        delete[] FileBuff;

        cout << "CompressSize:0x" << hex << CompressSize << endl;

        AutoSeededRandomPool Camelliaprng;
        SecByteBlock CamelliaKey(Camellia::DEFAULT_KEYLENGTH);
        Camelliaprng.GenerateBlock(CamelliaKey, CamelliaKey.size());
        byte CamelliaIv[Camellia::BLOCKSIZE];
        Camelliaprng.GenerateBlock(CamelliaIv, sizeof(CamelliaIv));

        // Test
        cout << "CamelliaKeySize:" << CamelliaKey.size() << endl;
        if (CamelliaKey.size() > Camellia::DEFAULT_KEYLENGTH)
            return E("CamelliaKey len over than DEFAULT_KEYLENGTH");

        Key_Index.KeyAfterCompress.KeySize = CamelliaKey.size();
        Key_Index.KeyAfterCompress.IvSize = sizeof(CamelliaIv);
        memcpy(Key_Index.KeyAfterCompress.Key, CamelliaKey.data(), CamelliaKey.size());
        memcpy(Key_Index.KeyAfterCompress.Iv, CamelliaIv, sizeof(CamelliaIv));

        BYTE* SecCryptFileBuff = new BYTE[CompressSize];
        try
        {
            EAX<Camellia>::Encryption e;
            e.SetKeyWithIV(CamelliaKey.data(), CamelliaKey.size(), CamelliaIv, sizeof(CamelliaIv));
            e.ProcessData(SecCryptFileBuff, CompressBuff, CompressSize);
        }
        catch (const Exception& e)
        {
            std::cerr << e.what() << std::endl;
            return E("Camellia Encrypt Error");
        }
        delete[] CompressBuff;

        cout << "compress and encrypt over" << endl;

        strcpy(CPK_Index.FileName, fnm.c_str());
        CPK_Index.FileSize = FileSize;
        CPK_Index.CompressFileSize = CompressSize;
        CPK_Index.Offset = pos;
        
        BYTE* IndexBuff = new BYTE[sizeof(CPKIndex)];
        memmove(IndexBuff, &CPK_Index, sizeof(CPKIndex));

        char* IndexHash = new char[SHA256::DIGESTSIZE];
        GenSHA256(IndexBuff, sizeof(CPKIndex), &IndexHash);
        memcpy(Key_Index.IndexHash, IndexHash, SHA256::DIGESTSIZE);
        for (int i = 0; i < sizeof(CPKIndex); i++)
            IndexBuff[i] ^= Key_Index.IndexHash[i % SHA256::DIGESTSIZE];

        BYTE* KeyIndexBuff = new BYTE[sizeof(KeyIndex)];
        memmove(KeyIndexBuff, &Key_Index, sizeof(KeyIndex));
        for (int i = 0; i < sizeof(KeyIndex); i++)
            KeyIndexBuff[i] ^= KEY_TOP_KEY;

        fwrite(IndexBuff, sizeof(CPKIndex), 1, cpk);
        delete[] IndexBuff;
        fwrite(KeyIndexBuff, sizeof(KeyIndex), 1, key);
        delete[] KeyIndexBuff;
        fseek(cpk, sizeof(CPKHeader) + FilePool.size() * sizeof(CPKIndex) + pos, SEEK_SET);
        pos += CompressSize;
        fwrite(SecCryptFileBuff, CompressSize, 1, cpk);
        delete[] SecCryptFileBuff;
        count += 1;
        fseek(cpk, sizeof(CPKHeader) + count * sizeof(CPKIndex), SEEK_SET);
    }
    cout << "over" << endl;
    fclose(cpk);
    fclose(key);
    system("pause");
    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
