### 1. Basic YARA Rule for UPX-packed Executables

**Perform String Analysis**:
```bash
Kailez@htb[/htb]$ strings svchost.exe
```

**Sample YARA Rule**:
```yara
rule UPX_packed_executable {
    meta:
        description = "Detects UPX-packed executables"
    strings: 
        $string_1 = "UPX0"
        $string_2 = "UPX1"
        $string_3 = "UPX2"
    condition:
        all of them
}
```

### 2. Generating a YARA Rule with yarGen

**Command**:
```bash
Kailez@htb[/htb]$ python3 yarGen.py -m /home/htb-student/temp -o htb_sample.yar
```

**Result**:
```bash
Kailez@htb[/htb]$ cat htb_sample.yar
```

### 3. Manual YARA Rule Development Examples

#### Example 1: ZoxPNG RAT Used by APT17
1. **String Analysis**:
   ```bash
   Kailez@htb[/htb]$ strings legit.exe
   ```
2. **Calculate Imphash**:
   ```bash
   Kailez@htb[/htb]$ python3 imphash_calc.py /home/htb-student/Samples/YARASigma/legit.exe
   ```

**APT17 YARA Rule**:
```yara
import "pe"

rule APT17_Malware_Oct17_Gen {
    meta:
        description = "Detects APT17 malware"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://goo.gl/puVc9q"
        date = "2017-10-03"
        hash1 = "0375b4216334c85a4b29441a3d37e61d7797c2e1cb94b14cf6292449fb25c7b2"
        hash2 = "07f93e49c7015b68e2542fc591ad2b4a1bc01349f79d48db67c53938ad4b525d"
        hash3 = "ee362a8161bd442073775363bf5fa1305abac2ce39b903d63df0d7121ba60550"
    strings:
        $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" fullword ascii
        $x2 = "http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus&tbnid=aLW4-J8Q1lmYBM" ascii
        $s1 = "hWritePipe2 Error:%d" fullword ascii
        $s2 = "Not Support This Function!" fullword ascii
        $s3 = "Cookie: SESSIONID=%s" fullword ascii
        $s4 = "http://0.0.0.0/1" fullword ascii
        $s5 = "Content-Type: image/x-png" fullword ascii
        $s6 = "Accept-Language: en-US" fullword ascii
        $s7 = "IISCMD Error:%d" fullword ascii
        $s8 = "[IISEND=0x%08X][Recv:] 0x%08X %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and (
            pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9" or
            1 of ($x*) or
            6 of them
        )
}
```

#### Example 2: Neuron Used by Turla

**Reverse Engineering with `monodis`**:
```bash
Kailez@htb[/htb]$ monodis --output=code Microsoft.Exchange.Service.exe
Kailez@htb[/htb]$ cat code
```

**Neuron Service YARA Rule**:
```yara
rule neuron_functions_classes_and_vars {
    meta:
        description = "Rule for detection of Neuron based on .NET functions and class names"
        author = "NCSC UK"
        reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
        reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
    strings:
        $class1 = "StorageUtils" ascii
        $class2 = "WebServer" ascii
        $func1 = "AddConfigAsString" ascii
        $func2 = "EncryptScript" ascii
        $dotnetMagic = "BSJB" ascii
    condition:
        uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550 and $dotnetMagic and 6 of them
}
```

#### Example 3: Stonedrill Used in Shamoon 2.0 Attacks

**Entropy Analysis**:
```bash
Kailez@htb[/htb]$ python3 entropy_pe_section.py -f /home/htb-student/Samples/YARASigma/sham2.exe
```

**Stonedrill YARA Rule**:
```yara
import "pe"
import "math"

rule susp_file_enumerator_with_encrypted_resource_101 {
    meta:
        copyright = "Kaspersky Lab"
        description = "Generic detection for samples that enumerate files with encrypted resource called 101"
        reference = "https://securelist.com/from-shamoon-to-stonedrill/77725/"
        hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
    strings:
        $mz = "This program cannot be run in DOS mode."
        $a1 = "FindFirstFile" ascii wide nocase
        $a3 = "FindResource" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and all of them and filesize < 700000 and
        pe.number_of_sections > 4 and pe.number_of_signatures == 0 and
        pe.number_of_resources > 1 and pe.number_of_resources < 15 and
        for any i in (0..pe.number_of_resources - 1):
        ( (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and
          pe.resources[i].id == 101 and pe.resources[i].length > 20000 and
          pe.resources[i].language == 0 and
          not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
        )
}
```

---

### **Resources for YARA Rule Development**

- **Official Documentation**: [YARA Documentation](https://yara.readthedocs.io/)
- **Kaspersky Guide**: Effective YARA Rule Development