
## BlowFish

If you use BlowFish to encrypt / decrypt small strings such as passwords, use the following to strip off padding

```cs
var blowFish = BlowFish.Create();
    
blowFish.GenerateIV();
blowFish.GenerateKey();

var transform = blowFish.CreateEncryptor();
var testString = "Why I got you on my mind? by Ellie Goulding";
var inputBuffer = System.Text.Encoding.UTF8.GetBytes(testString);

// outputBuffer must be a multiple of the BlockSize (8);
byte[] encryptedBytes = EncryptionUtil.CreateOutputBuffer(inputBuffer, blowFish.BlockSize);

transform.TransformBlock(inputBuffer, 0, inputBuffer.length, encryptedBytes, 0);

// Use TransformFinalBlock to strip off the trailing zeros that are required by BlowFish
blowFish.PaddingMode = PaddingMode.None;
transform = blowFish.CreateDecryptor();
var decryptedBytes = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
var decryptedText = Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length)
```