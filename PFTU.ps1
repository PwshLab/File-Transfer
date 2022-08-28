function Send-DataPacket
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $Data,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [IO.Stream]
        $Stream
    )

    if (!$Stream.CanWrite)
    {
        Write-Warning -Message "Data could not be sent"
        return
    }

    $DataLengthBytes = [BitConverter]::GetBytes([uint64]$Data.Length)
    $Stream.Write($DataLengthBytes, 0, $DataLengthBytes.Length) | Out-Null
    $Stream.Write($Data, 0, $Data.Length) | Out-Null
    $Stream.Flush() | Out-Null
}

function Receive-DataPacket
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [IO.Stream]
        $Stream
    )

    if (!$Stream.CanRead)
    {
        Write-Warning -Message "Data could not be read"
        return
    }

    $DataLengthBytes = [Array]::CreateInstance([byte], 8)
    $Stream.Read($DataLengthBytes, 0, $DataLengthBytes.Length) | Out-Null
    $DataLength = [BitConverter]::ToUInt64($DataLengthBytes, 0)
    $Data = [Array]::CreateInstance([byte], $DataLength)
    $Stream.Read($Data, 0, $Data.Length) | Out-Null

    return $Data
}

function Convert-PSCustomObject
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "FromObject")]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]
        $Object,
        [Parameter(Mandatory = $true, ParameterSetName = "ToObject")]
        [byte[]]
        $Data
    )

    if ($Object)
    {
        $Json = ConvertTo-Json -InputObject $Object
        $Data = [Text.Encoding]::Unicode.GetBytes($Json)
        return $Data
    }
    if ($Data)
    {
        $Json = [Text.Encoding]::Unicode.GetString($Data)
        $Object = ConvertFrom-Json -InputObject $Json
        return $Object
    }
}

function Start-PFTUReceiver
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FolderPath = ".\Output",
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [int]
        $Port = 8998,
        [Parameter(Mandatory = $false)]
        [Switch]
        $RequestCompression,
        [Parameter(Mandatory = $false)]
        [Switch]
        $RequestEncryption
    )

    if (![IO.Directory]::Exists($FolderPath))
    {
        New-Item -Path $FolderPath -ItemType Directory -Force | Out-Null
        Write-Verbose "Directory $FolderPath does not exist. Creating Directory..."
    }

    Write-Verbose "Starting server on port $Port..."

    $Server = [Net.Sockets.TcpListener]::new([ipaddress]::Any, $Port)
    $Server.Start()

    if (!$Server.Server.IsBound)
    {
        Write-Warning -Message "Could not start receiver"
        $Server.Stop()
        return
    }

    Write-Verbose "Waiting for client to connect to server..."
    $Client = $Server.AcceptTcpClient()
    $Stream = $Client.GetStream()
    Write-Verbose "Client connected"

    Write-Verbose "Reading Greet Message from client..."
    $Data = Receive-DataPacket -Stream $Stream
    $GreetMessage = Convert-PSCustomObject -Data $Data

    $Compression = $GreetMessage.Compression -or $RequestCompression
    $Encryption = $GreetMessage.Encryption -or $RequestEncryption

    if ($Compression)
    {
        Write-Verbose "Compression is now enabled"
    }

    if ($Encryption)
    {
        Write-Verbose "Encryption is now enabled"
    }

    $ResponseMessage = [PSCustomObject]@{
        Compression = $Compression
        Encryption = $Encryption
    }

    Write-Verbose "Sending confirmation response to client..."
    $Data = Convert-PSCustomObject -Object $ResponseMessage
    Send-DataPacket -Stream $Stream -Data $Data
    Write-Verbose "Response sent"

    if ($Encryption)
    {   
        Write-Verbose "Creating RSA configuration..."
        $RSA = [Security.Cryptography.RSA]::Create()
        $RSAParameters = $RSA.ExportParameters($false)
        $RSAPadding = [Security.Cryptography.RSAEncryptionPadding]::CreateOaep([Security.Cryptography.HashAlgorithmName]::SHA512)

        $RSAMessage = [PSCustomObject]@{
            Exponent = $RSAParameters.Exponent
            Modulus = $RSAParameters.Modulus
        }

        Write-Verbose "Sending RSA information to client..."
        $Data = Convert-PSCustomObject -Object $RSAMessage
        Send-DataPacket -Stream $Stream -Data $Data

        Write-Verbose "Receiving RSA encrypted AES information from client..."
        $Data = Receive-DataPacket -Stream $Stream
        Write-Verbose "Decrpting AES information..."
        $Data = $RSA.Decrypt($Data, $RSAPadding)
        $AESMessage = Convert-PSCustomObject -Data $Data
        Write-Verbose "Configuring AES..."
        $AES = [Security.Cryptography.Aes]::Create()
        $AES.Key = $AESMessage.Key
        $AES.IV = $AESMessage.IV
        Write-Verbose "AES configured"
    }

    Write-Verbose "Receiving file data from client..."
    $Data = Receive-DataPacket -Stream $Stream
    $FileData = [IO.MemoryStream]::new($FileData)
    Write-Verbose "Data received"

    if ($Encryption)
    {   
        Write-Verbose "Decrypting file data..."
        $MemoryStream = [IO.MemoryStream]::new()
        $CryptoStream = [Security.Cryptography.CryptoStream]::new($FileData, $AES.CreateDecryptor(), [Security.Cryptography.CryptoStreamMode]::Read)
        $CryptoStream.CopyTo($MemoryStream)
        $FileData = $MemoryStream
        $CryptoStream.Dispose()
        Write-Verbose "Data decrypted"
    }

    if ($Compression)
    {
        Write-Verbose "Decompressing file data..."
        $MemoryStream = [IO.MemoryStream]::new()
        $GZipStream = [IO.Compression.GZipStream]::new($FileData, [IO.Compression.CompressionMode]::Decompress)
        $GZipStream.CopyTo($MemoryStream)
        $FileData = $MemoryStream
        $GZipStream.Dispose()
        Write-Verbose "Data decompressed"
    }

    Write-Verbose "Hashing file data..."
    $Sha512 = [Security.Cryptography.SHA512]::Create()
    $Hash = $Sha512.ComputeHash($FileData)

    if ($Hash -ne $GreetMessage.SHA512)
    {   
        Write-Verbose "File hashes are not identical"
        Write-Warning -Message "File corrupted"
        return
    }

    Write-Verbose "Writing file data to disk..."
    $FilePath = Join-Path -Path $FolderPath -ChildPath $GreetMessage.FileName
    $Data = $FileData.ToArray()
    [IO.File]::WriteAllBytes($FilePath, $Data)

    Write-Verbose "Closing server..."
    $Stream.Dispose()
    $Server.Stop()
    $Server.Dispose()
}

function Start-PFTUSender
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FilePath,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Address,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [int]
        $Port = 8998,
        [Parameter(Mandatory = $false)]
        [Switch]
        $RequestCompression,
        [Parameter(Mandatory = $false)]
        [Switch]
        $RequestEncryption
    )

    if (![IO.File]::Exists($FilePath))
    {
        Write-Warning -Message "File does not exist"
        return
    }

    Write-Verbose "Reading file data from disk..."
    $FileName = $FilePath.Split("\")[-1]
    $FileData = [IO.File]::ReadAllBytes($FilePath)

    Write-Verbose "Hashing file data..."
    $Sha512 = [Security.Cryptography.SHA512]::Create()
    $Hash = $Sha512.ComputeHash($FileData)

    Write-Verbose "Connecting to address $Address at port $Port..."
    $Client = [Net.Sockets.TcpClient]::new($Address, $Port)

    if (!$Client.Connected)
    {
        Write-Verbose "Client could not connect to server"
        Write-Warning -Message "Could not start sender"
        $Client.Dispose()
        return
    }

    $Stream = $Client.GetStream()

    $GreetMessage = [PSCustomObject]@{
        Compression = $RequestCompression
        Encryption = $RequestEncryption
        SHA512 = $Hash
        FileName = $FileName
    }

    Write-Verbose "Sending Greet Message to server..."
    $Data = Convert-PSCustomObject -Object $GreetMessage
    Send-DataPacket -Stream $Stream -Data $Data
    Write-Verbose "Message sent"

    Write-Verbose "Receiving response from server..."
    $Data = Receive-DataPacket -Stream $Stream
    $ResponseMessage = Convert-PSCustomObject -Data $Data
    Write-Verbose "Response received"

    $Compression = $ResponseMessage.Compression
    $Encryption = $ResponseMessage.Encryption

    if ($Compression)
    {
        Write-Verbose "Compression is now enabled"
    }

    if ($Encryption)
    {
        Write-Verbose "Encryption is now enabled"
    }

    Write-Verbose "Loading file data into memory stream..."
    $FileData = [IO.MemoryStream]::new($FileData)

    if ($Compression)
    {   
        Write-Verbose "Compressing file data..."
        $MemoryStream = [IO.MemoryStream]::new()
        $GZipStream = [IO.Compression.GZipStream]::new($MemoryStream, [IO.Compression.CompressionMode]::Compress)
        $FileData.CopyTo($GZipStream)
        $FileData = $MemoryStream
        $GZipStream.Dispose()
        Write-Verbose "File data compressed"
    }

    if ($Encryption)
    {   
        Write-Verbose "Receiving RSA information from server..."
        $Data = Receive-DataPacket -Stream $Stream
        $RSAMessage = Convert-PSCustomObject -Data $Data
        Write-Verbose "Configuring RSA..."
        $RSAParameters = [Security.Cryptography.RSAParameters]::new()
        $RSAParameters.Exponent = $RSAMessage.Exponent
        $RSAParameters.Modulus = $RSAMessage.Modulus
        $RSA = [Security.Cryptography.RSA]::Create($RSAParameters)
        $RSAPadding = [Security.Cryptography.RSAEncryptionPadding]::CreateOaep([Security.Cryptography.HashAlgorithmName]::SHA512)
        Write-Verbose "RSA configured"

        Write-Verbose "Creating AES configuration..."
        $AES = [Security.Cryptography.Aes]::Create()
        $AESMessage = [PSCustomObject]@{
            Key = $AES.Key
            IV = $AES.IV
        }

        Write-Verbose "Encrypting AES information with RSA..."
        $Data = Convert-PSCustomObject -Object $AESMessage
        $Data = $RSA.Encrypt($Data, $RSAPadding)
        Write-Verbose "Sending RSA enrcryped AES information to server..."
        Send-DataPacket -Stream $Stream -Data $Data

        Write-Verbose "Encrypting file data with AES..."
        $MemoryStream = [IO.MemoryStream]::new()
        $CryptoStream = [Security.Cryptography.CryptoStream]::new($FileData, $AES.CreateEncryptor(), [Security.Cryptography.CryptoStreamMode]::Read)
        $CryptoStream.CopyTo($MemoryStream)
        $FileData = $MemoryStream
        $CryptoStream.Dispose()
        Write-Verbose "Encrypted file data with AES"
    }

    Write-Verbose "Sending file data to server..."
    $Data = $FileData.ToArray()
    Send-DataPacket -Stream $Stream -Data $Data

    Write-Verbose "Closing client..."
    $FileData.Dispose()
    $Stream.Dispose()
    $Client.Dispose()
}