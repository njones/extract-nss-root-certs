// Copyright 2012 Google Inc. All Rights Reserved.
// Author: agl@chromium.org (Adam Langley)

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This utility parses Mozilla's certdata.txt and extracts a list of trusted
// certificates in PEM form.
//
// A current version of certdata.txt can be downloaded from:
//   https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
package nss

import (
	"bufio"
	"bytes"
	"crypto"
	_ "crypto/md5"
	"crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
)

// Object represents a collection of attributes from the certdata.txt file
// which are usually either certificates or trust records.
type Object struct {
	attrs        map[string]Attribute
	startingLine int // the line number that the object started on.
}

type Attribute struct {
	attrType string
	value    []byte
}

var (
	// IgnoreList maps from CKA_LABEL values (from the upstream roots file)
	// to an optional comment which is displayed when skipping matching
	// certificates.
)


// parseIgnoreList parses the ignore-list file into IgnoreList
func ParseIgnoreList(IgnoreListFile io.Reader) (il map[string]string) {
	if il == nil {
		il = make(map[string]string)
	}
	in := bufio.NewScanner(IgnoreListFile)

	for in.Scan() {
		line := in.Text()
		if split := strings.SplitN(line, "#", 2); len(split) == 2 {
			// this line has an additional comment
			il[strings.TrimSpace(split[0])] = strings.TrimSpace(split[1])
		} else {
			il[line] = ""
		}
	}
	return
}

func ParseLicenseBlock(in *bufio.Scanner, ln int) (lineNo int, license, cvsId string) {

	license += in.Text()+"\n"   // Add this line to the license string
	
	// Loop through the next lines until we get to an blank line
	for in.Scan() {

		// Advance the line count and grab the line
		ln += 1
		line := in.Text()

		// Check to see if there is a CVS_ID line within the license
		if strings.HasPrefix(line, "CVS_ID ") {
			cvsId = line[7:]
			continue
		}

		// If the line is blank then we can exit out of the license loop
		if len(line) == 0 { break }
		license += line+"\n" // Add this line to the license string.
	}
	return ln, license, cvsId
}

func ParseMultiLineOctal(in *bufio.Scanner, ln int) (lineNo int, value []byte) {
	// Loop through the next lines (inner-loop 2)
	for in.Scan() {
		
		// Advance the line count and grab the line
		ln += 1
		line := in.Text()

		// If we've hit the end of the block then break out of (inner-loop 2) and go back to inner-loop 1
		if line == "END" { break }
		
		// Split all of the octal encodings for the line out. 
		for _, octalStr := range strings.Split(line, `\`) {
			if len(octalStr) == 0 {
				continue
			}

			// Parse the string value to a int8 (byte) value
			v, err := strconv.ParseUint(octalStr, 8, 8)
			if err != nil {
				log.Fatalf("error converting octal string '%s' on line %d", octalStr, lineNo)
			}

			// Append all of the bytes
			value = append(value, byte(v))
		}
	}

	return ln, value
}

// parseInput parses a certdata.txt file into it's license blob, the CVS id (if
// included) and a set of Objects.
func ParseInput(inFile io.Reader) (license, cvsId string, objects []*Object) {
	in := bufio.NewScanner(inFile)
	
	var lineNo int
	var hasLicense bool
	var hasBeginData bool
	var currentObject *Object

	for in.Scan() {
		
		lineNo += 1
		line := in.Text()

		// Collect the license block
		// Loop until we get the line "This Source Code" ...
		if strings.Contains(line, "This Source Code") {
			hasLicense = true // We have found a license, so set this check to true.
			lineNo, license, cvsId = ParseLicenseBlock(in, lineNo)
		}

		// Loop until we get to the line BEGINDATA
		if line == "BEGINDATA" {
			hasBeginData = true

			// Now finish the scanning of the document here (inner-loop 1). We shouldn't need to go back to the outer loop
			for in.Scan() {
		
				// Advance the line count and grab the line
				lineNo += 1
				line := in.Text()

				// Skip all of the comments
				if len(line) == 0 || line[0] == '#' {
					continue
				}
				
				var value []byte
				words := strings.Fields(line)
				
				// If we have the words Mutli-Line, then the next block of lines needs
				// to be converted from encoded octals to binary
				if len(words) == 2 && words[1] == "MULTILINE_OCTAL" {
					lineNo, value = ParseMultiLineOctal(in, lineNo)
				} else if len(words) < 3 {
					log.Fatalf("Expected three or more values on line %d, but found %d", lineNo, len(words))
				} else {
					value = []byte(strings.Join(words[2:], " "))
				}

				if words[0] == "CKA_CLASS" {
					
					// Save the old object only after we have started a new object
					if currentObject != nil {
						objects = append(objects, currentObject)
					}

					// Start of a new object.
					currentObject = new(Object)
					currentObject.attrs = make(map[string]Attribute)
					currentObject.startingLine = lineNo
				}

				if currentObject == nil {
					log.Fatalf("Found attribute on line %d which appears to be outside of an object", lineNo)
				}

				currentObject.attrs[words[0]] = Attribute{
					attrType: words[1],
					value:    value,
				}
			}
			continue
		}
	}

	if !hasLicense {
		log.Fatalf("Read whole input and failed to find beginning of license")
	}

	if !hasBeginData {
		log.Fatalf("Read whole input and failed to find BEGINDATA")
	}

	if currentObject != nil {
		objects = append(objects, currentObject)
	}

	return
}

type Block struct {
	Label string
	Pem *pem.Block
	X509 *x509.Certificate
}

func TrustedCertificates(objects []*Object, ignoreList map[string]string) []Block {
	return certs(objects, ignoreList, false)
}

func AllCertificates(objects []*Object, ignoreList map[string]string) []Block {
	return certs(objects, ignoreList, true)
}

// outputTrustedCerts writes a series of PEM encoded certificates to out by
// finding certificates and their trust records in objects.
func certs(objects []*Object, ignoreList map[string]string, includeUntrusted bool) (blocks []Block) {
	certs := filterObjectsByClass(objects, "CKO_CERTIFICATE")
	trusts := filterObjectsByClass(objects, "CKO_NSS_TRUST")

	for _, cert := range certs {
		derBytes := cert.attrs["CKA_VALUE"].value
		hash := sha1.New()
		hash.Write(derBytes)
		digest := hash.Sum(nil)

		label := string(cert.attrs["CKA_LABEL"].value)
		if comment, present := ignoreList[strings.Trim(label, "\"")]; present {
			var sep string
			if len(comment) > 0 {
				sep = ": "
			}
			log.Printf("Skipping explicitly ignored certificate: %s%s%s", label, sep, comment)
			continue
		}

		x509, err := x509.ParseCertificate(derBytes)
		if err != nil {
			// This is known to occur because of a broken certificate in NSS.
			// https://bugzilla.mozilla.org/show_bug.cgi?id=707995
			log.Printf("Failed to parse certificate starting on line %d: %s", cert.startingLine, err)
			continue
		}

		// TODO(agl): wtc tells me that Mozilla might get rid of the
		// SHA1 records in the future and use issuer and serial number
		// to match trust records to certificates (which is what NSS
		// currently uses). This needs some changes to the crypto/x509
		// package to keep the raw names around.

		var trust *Object
		for _, possibleTrust := range trusts {
			if bytes.Equal(digest, possibleTrust.attrs["CKA_CERT_SHA1_HASH"].value) {
				trust = possibleTrust
				break
			}
		}

		if trust == nil {
			log.Fatalf("No trust found for certificate object starting on line %d (sha1: %x)", cert.startingLine, digest)
		}

		trustType := trust.attrs["CKA_TRUST_SERVER_AUTH"].value
		if len(trustType) == 0 {
			log.Fatalf("No CKA_TRUST_SERVER_AUTH found in trust starting at line %d", trust.startingLine)
		}

		var trusted bool
		switch string(trustType) {
		case "CKT_NSS_NOT_TRUSTED":
			// An explicitly distrusted cert
			trusted = false
		case "CKT_NSS_TRUSTED_DELEGATOR":
			// A cert trusted for issuing SSL server certs.
			trusted = true
		case "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_MUST_VERIFY_TRUST":
			// A cert not trusted for issuing SSL server certs, but is trusted for other purposes.
			trusted = false
		default:
			log.Fatalf("Unknown trust value '%s' found for trust record starting on line %d", trustType, trust.startingLine)
		}

		if !trusted && !includeUntrusted {
			continue
		}

		block := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
		blocks = append(blocks, Block{label, block, x509})
	}

	return
}

// nameToString converts name into a string representation containing the
// CommonName, Organization and OrganizationalUnit.
func Name(name pkix.Name) string {
	ret := ""
	if len(name.CommonName) > 0 {
		ret += "CN=" + name.CommonName
	}

	if org := strings.Join(name.Organization, "/"); len(org) > 0 {
		if len(ret) > 0 {
			ret += " "
		}
		ret += "O=" + org
	}

	if orgUnit := strings.Join(name.OrganizationalUnit, "/"); len(orgUnit) > 0 {
		if len(ret) > 0 {
			ret += " "
		}
		ret += "OU=" + orgUnit
	}

	return ret
}

func Fingerprint(hashFunc crypto.Hash, data []byte) string {
	hash := hashFunc.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	// Print out Hex numbers with a space, then replace that space with a colon.
	return strings.Replace(fmt.Sprintf("% x", digest), " ", ":", -1)
}

// unescapeLabel unescapes "\xab" style hex-escapes.
func UnescapeLabel(escaped string) string {

	// The variable that will hold the bytes of the output string
	var b []byte

	// Loop through the string and split on `\x`
	fn := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		
		// If you find the string `\x` then we have a hex character
		if string(data[0:1]) == `\x` {

			// We know that the encoding will always take up 4 bytes (i.e. "\xab"), so just advance the counter by that much.
			advance = 4

			// Grab the hex value of the string as a real number
			tb, err := strconv.ParseUint(string(data[0:1]), 16, 8)
			if err != nil {
				// We have an error, so return the error, and advance the token by one.
				return 1, []byte{data[0]}, err
			}
			
			// Take the number that was converted from a string, and convert it to a byte.
			token = []byte{byte(tb)}
			
			// Advance the scanner by 4 bytes, then return the actual single byte generated from the hex number
			return advance, token, nil
		}

		// Nothing was found, so advance the scanner by one, and return the previous byte as it was.
		return 1, []byte{data[0]}, nil // Advance one byte at a time
	}

	// Set up a new scanner, and add the escaped string to it.
	sn := bufio.NewScanner(strings.NewReader(escaped))
	sn.Split(fn)

	// Loop through all of the tokens appending bytes until we hit a EOF.
	for sn.Scan() {
		b = append(b, sn.Bytes()...)
	}

	// Convert all of the actual bytes to a string.
	return string(b)
}

// filterObjectsByClass returns a subset of in where each element has the given
// class.
func filterObjectsByClass(in []*Object, class string) (out []*Object) {
	for _, object := range in {
		if string(object.attrs["CKA_CLASS"].value) == class {
			out = append(out, object)
		}
	}
	return
}