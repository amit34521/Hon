/*
 * Created by SharpDevelop.
 * User: Amit
 * Date: 04-11-2018
 * Time: 07:15 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace FileDecryptor
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
		
		string decryptedContent = string.Empty;
		
		string encryptedInfo = string.Empty;
		
		private const int Keysize = 256;

        private const int DerivationIterations = 1000;
		
		public static string DecryptData(string cipherText, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }
		
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
            	encryptedInfo = streamReader.ReadToEnd();
            }
			
			MessageBox.Show("Content Loaded");
		}
		
		void SavePathClick(object sender, EventArgs e)
		{
			FolderBrowserDialog folderBrowser = new FolderBrowserDialog();
			if (folderBrowser.ShowDialog() == DialogResult.OK) {
				textBox2.Text = folderBrowser.SelectedPath;
			}
		}
		void DecryptNowClick(object sender, EventArgs e)
		{
			if(string.IsNullOrWhiteSpace(textBox3.Text))
			{
				MessageBox.Show("Please Enter Passwprd");
				textBox3.Focus();
			}
			else
			{
				decryptedContent = DecryptData(encryptedInfo , textBox3.Text);
				
				string fileName = textBox1.Text;
				int pos = fileName.LastIndexOf("\\");
				string file = fileName.Substring(pos + 1);
				string newFilePath = textBox2.Text + "\\Decrypted-" + file;
				using (StreamWriter writer = new StreamWriter(newFilePath))
				{
					writer.Write(decryptedContent);
				}
				MessageBox.Show("File Saved Successfully");
			}
		}
	}
}
