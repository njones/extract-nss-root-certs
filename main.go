package main

import (
	"flag"
	"github.com/njones/nss/nss"
	"fmt"
	"os"
	"log"

	"crypto"
	"encoding/pem"
	"strings"
	"strconv"
)

var (
	includedUntrustedFlag = flag.Bool("include-untrusted", false, "If set, untrusted certificates will also be included in the output")
	toFiles               = flag.Bool("to-files", false, "If set, individual certificate files will be created in the current directory")
	ignoreListFilename    = flag.String("ignore-list", "", "File containing a list of certificates to ignore")
)

func main() {

	flag.Parse()

	inFilename := "certdata.txt"
	if len(flag.Args()) == 1 {
		inFilename = flag.Arg(0)
	} else if len(flag.Args()) > 1 {
		fmt.Printf("Usage: %s [<certdata.txt file>]\n", os.Args[0])
		os.Exit(1)
	}

	il := make(map[string]string)

	//ignoreList := make(map[string]string)
	if *ignoreListFilename != "" {
		ignoreListFile, err := os.Open(*ignoreListFilename)
		if err != nil {
			log.Fatalf("Failed to open ignore-list file: %s", err)
		}
		il = nss.ParseIgnoreList(ignoreListFile)
		defer ignoreListFile.Close()
	}

	inFile, err := os.Open(inFilename)
	if err != nil {
		log.Fatalf("Failed to open input file: %s", err)
	}

	license, cvsId, objects := nss.ParseInput(inFile)
	defer inFile.Close()

	if !*toFiles {
		os.Stdout.WriteString(license)
		if len(cvsId) > 0 {
			os.Stdout.WriteString("CVS_ID " + cvsId + "\n")
		}
	}

	var f []nss.Block

	if *includedUntrustedFlag {
		f = nss.AllCertificates(objects, il)
	} else {
		f = nss.TrustedCertificates(objects, il)
	}

	for _, blox := range f {
		x509 := blox.X509
		label := blox.Label

		block := &pem.Block{Type: "CERTIFICATE", Bytes: x509.Raw}

		fmt.Println()
		fmt.Println("# Issuer:", nss.Field(x509.Issuer))
		fmt.Println("# Subject:", nss.Field(x509.Subject))
		fmt.Println("# Label:", label)
		fmt.Println("# Serial:", x509.SerialNumber.String())
		fmt.Println("# MD5 Fingerprint:", nss.Fingerprint(crypto.MD5, x509.Raw))
		fmt.Println("# SHA1 Fingerprint:", nss.Fingerprint(crypto.SHA1, x509.Raw))
		fmt.Println("# SHA256 Fingerprint:", nss.Fingerprint(crypto.SHA256, x509.Raw))
		pem.Encode(os.Stdout, block)
	}

	if *toFiles {
		filenames := make(map[string]bool)
		for _, x := range f {
			label := x.Label
			x509 := x.X509
			block := &pem.Block{Type: "CERTIFICATE", Bytes: x509.Raw}

			if strings.HasPrefix(label, "\"") {
				label = label[1:]
			}
			if strings.HasSuffix(label, "\"") {
				label = label[:len(label)-1]
			}
			// The label may contain hex-escaped, UTF-8 charactors.
			label = nss.DecodeHexEscapedString(label)
			label = strings.Replace(label, " ", "_", -1)
			label = strings.Replace(label, "/", "_", -1)

			filename := label
			for i := 2; ; i++ {
				if _, ok := filenames[filename]; !ok {
					break
				}

				filename = label + "-" + strconv.Itoa(i)
			}
			filenames[filename] = true

			file, err := os.Create(filename + ".pem")
			if err != nil {
				log.Fatalf("Failed to create output file: %s\n", err)
			}
			pem.Encode(file, block)
			file.Close()
			//out.WriteString(filename + ".pem\n")
			continue
		}
	}
}
