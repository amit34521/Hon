/*
 * Created by SharpDevelop.
 * User: Amit
 * Date: 04-11-2018
 * Time: 06:35 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace FileEncryptor
{
	/// <summary>
	/// Description of MainForm.
	/// </summary>
	public partial class MainForm : Form
	{
		public MainForm()
		{
			//
			// The InitializeComponent() call is required for Windows Forms designer support.
			//
			InitializeComponent();
			
			//
			// TODO: Add constructor code after the InitializeComponent() call.
			//
		}
		
		string fileContent = string.Empty;
		
		string encryptedInfo = string.Empty;
		
		private const int Keysize = 256;

        private const int DerivationIterations = 1000;
		
		void LoadClick(object sender, EventArgs e)
		{
			OpenFileDialog theDialog = new OpenFileDialog();
			theDialog.Title = "Open Text File";
			theDialog.Filter = "All files|*.*";
			theDialog.InitialDirectory = @"C:\";
			if (theDialog.ShowDialog() == DialogResult.OK) {
				textBox1.Text = theDialog.FileName;
			}
			
			using (StreamReader streamReader = new StreamReader(textBox1.Text))
            {
            	fileContent = streamReader.ReadToEnd();
            }
			
			MessageBox.Show("Content Loaded");
		}
		
		void EncryptClick(object sender, EventArgs e)
		{
			if(string.IsNullOrWhiteSpace(textBox2.Text))
			{
				MessageBox.Show("Please Enter Password to encrypt the string");
				textBox2.Focus();
			}
			else
			{
				encryptedInfo = EncryptInfo(fileContent , textBox2.Text);
				
				if(string.IsNullOrWhiteSpace(encryptedInfo))
					MessageBox.Show("Encryption Failed. Try Again");
				else
					MessageBox.Show("Encryption Successful");
			}
		}
		
		public static string EncryptInfo(string plainText, string passPhrase)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }
		
		private static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
		
		void Button1Click(object sender, EventArgs e)
		{
			FolderBrowserDialog folderBrowser = new FolderBrowserDialog();
			if (folderBrowser.ShowDialog() == DialogResult.OK) {
				textBox3.Text = folderBrowser.SelectedPath;
			}
		}
		void Button2Click(object sender, EventArgs e)
		{
			string fileName = textBox1.Text;
			int pos = fileName.LastIndexOf("\\");
			string file = fileName.Substring(pos + 1);
			string newFilePath = textBox3.Text + "\\" + file;
			using (StreamWriter writer = new StreamWriter(newFilePath))
			{
				writer.Write(encryptedInfo);
			}
			MessageBox.Show("File Saved Successfully");
		}
		
	}
}
