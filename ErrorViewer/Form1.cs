using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ErrorViewer
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                var key = new RSAParameters()
                {
                    //D = new byte[] { 9, 162, 25, 165, 196, 78, 187, 124, 249, 9, 107, 119, 251, 240, 23, 20, 100, 5, 233, 167, 17, 96, 120, 39, 136, 172, 40, 29, 14, 33, 18, 110, 89, 0, 160, 61, 129, 208, 187, 20, 200, 123, 24, 128, 233, 33, 114, 138, 136, 179, 17, 75, 62, 2, 172, 102, 177, 109, 165, 166, 215, 126, 47, 55, 7, 78, 60, 241, 46, 128, 143, 213, 156, 170, 121, 253, 105, 26, 95, 6, 143, 4, 27, 196, 154, 83, 145, 175, 36, 243, 89, 188, 79, 169, 197, 118, 51, 41, 42, 193, 32, 18, 129, 45, 214, 203, 40, 245, 190, 106, 186, 206, 172, 41, 68, 208, 251, 220, 210, 73, 36, 209, 211, 73, 225, 166, 11, 189 },
                    //DP = new byte[] { 23, 10, 77, 114, 154, 63, 146, 58, 61, 0, 73, 222, 175, 42, 38, 117, 16, 132, 102, 81, 16, 190, 140, 25, 137, 38, 104, 9, 4, 64, 78, 144, 32, 43, 28, 150, 117, 59, 171, 19, 94, 179, 155, 180, 216, 246, 14, 107, 72, 35, 245, 138, 49, 62, 214, 2, 71, 244, 137, 253, 205, 17, 70, 43 },
                    //DQ = new byte[] { 244, 207, 137, 183, 45, 246, 208, 48, 77, 221, 226, 209, 2, 16, 199, 10, 117, 155, 64, 17, 226, 253, 47, 43, 195, 17, 206, 108, 101, 152, 229, 10, 1, 22, 182, 130, 236, 83, 141, 50, 218, 176, 35, 98, 34, 145, 86, 152, 55, 158, 156, 204, 247, 184, 122, 73, 255, 243, 46, 201, 64, 1, 149, 93 },
                    Exponent = new byte[] { 1, 0, 1 },
                    //InverseQ = new byte[] { 166, 101, 146, 7, 247, 97, 5, 116, 28, 229, 39, 17, 174, 58, 253, 123, 55, 174, 168, 164, 74, 108, 231, 233, 201, 230, 242, 131, 238, 204, 208, 45, 152, 229, 97, 154, 208, 119, 206, 244, 211, 14, 46, 39, 79, 52, 190, 202, 134, 0, 245, 15, 14, 175, 54, 5, 178, 234, 6, 224, 3, 165, 4, 152 },
                    Modulus = new byte[] { 199, 209, 235, 83, 229, 243, 67, 47, 206, 155, 52, 106, 107, 93, 98, 30, 204, 74, 49, 108, 137, 56, 59, 245, 136, 159, 216, 142, 201, 91, 206, 135, 6, 8, 197, 58, 15, 43, 201, 47, 248, 220, 37, 28, 53, 46, 133, 197, 132, 227, 215, 214, 34, 109, 210, 167, 202, 58, 5, 78, 103, 100, 0, 151, 100, 142, 8, 61, 54, 153, 171, 232, 90, 28, 184, 202, 190, 21, 103, 23, 180, 178, 115, 201, 177, 85, 250, 215, 61, 164, 164, 47, 64, 17, 131, 162, 48, 137, 60, 255, 116, 85, 137, 134, 33, 201, 32, 242, 255, 249, 149, 184, 129, 235, 62, 16, 222, 102, 39, 43, 222, 46, 75, 114, 74, 249, 159, 151 }//,
                    //P = new byte[] { 202, 181, 209, 127, 134, 141, 138, 46, 235, 57, 222, 160, 241, 37, 211, 58, 37, 236, 59, 182, 37, 184, 192, 117, 77, 162, 20, 206, 124, 169, 11, 135, 31, 54, 162, 156, 40, 89, 234, 45, 161, 187, 1, 73, 136, 181, 111, 197, 240, 95, 12, 87, 204, 229, 175, 0, 61, 69, 45, 210, 172, 2, 114, 187 },
                    //Q = new byte[] { 252, 89, 151, 105, 46, 192, 98, 218, 208, 204, 90, 225, 163, 202, 231, 52, 178, 126, 52, 116, 30, 190, 21, 65, 111, 118, 167, 141, 13, 75, 240, 37, 182, 108, 65, 39, 183, 115, 226, 104, 46, 76, 240, 58, 182, 202, 213, 189, 127, 217, 43, 149, 196, 107, 255, 155, 121, 199, 29, 227, 238, 54, 222, 213 }
                };

                string data = File.ReadAllText(@"E:\PacoteExtraçãoCompleto.xml");

                //byte[] data = File.ReadAllBytes(@"E:\PacoteExtraçãoCompleto.encr");
                //UnicodeEncoding byteConverter = new UnicodeEncoding();
                //byte[] data = byteConverter.GetBytes("Data to Encrypt");

                //var decryptedData = RSADecrypt(data, key, false);
                //UnicodeEncoding byteConverter = new UnicodeEncoding();
                //MessageBox.Show(byteConverter.GetString(decryptedData));

                File.WriteAllText(@"E:\PacoteExtraçãoCompleto.encr", Encrypt(data, key, false));
            }
            catch (Exception exp)
            {
                MessageBox.Show(exp.Message);
            }

        }





        static public string Encrypt(string dataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                using (MemoryStream allData = new MemoryStream())
                {
                    using (Rijndael rijAlg = Rijndael.Create())
                    {
                        using (BinaryWriter bwConcat = new BinaryWriter(allData))
                        {
                            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                            {

                                //Import the RSA Key information. This only needs
                                //toinclude the public key information.
                                RSA.ImportParameters(RSAKeyInfo);

                                //Encrypt the passed byte array and specify OAEP padding.  
                                //OAEP padding is only available on Microsoft Windows XP or
                                //later.  
                                byte[] encKey = RSA.Encrypt(rijAlg.Key, DoOAEPPadding);
                                bwConcat.Write(encKey);
                                byte[] encIV = RSA.Encrypt(rijAlg.IV, DoOAEPPadding);
                                bwConcat.Write(encIV);
                            }

                            // Create a decrytor to perform the stream transform.
                            ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                            // Create the streams used for encryption.
                            using (MemoryStream msEncrypt = new MemoryStream())
                            {
                                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                                {
                                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                                    {
                                        //Write all data to the stream.
                                        swEncrypt.Write(dataToEncrypt);
                                    }
                                }


                                bwConcat.Write(msEncrypt.ToArray());
                            }
                        }

                    }

                    return Convert.ToBase64String(allData.ToArray());
                }
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                MessageBox.Show(e.Message);

                return null;
            }

        }


        static public string Decrypt(string dataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            byte[] data = Convert.FromBase64String(dataToDecrypt);

            using (Rijndael algoritmo = Rijndael.Create())
            {
                using (MemoryStream msKey = new MemoryStream(data, 0, 256))
                {
                    using (BinaryReader srKey = new BinaryReader(msKey))
                    {
                        using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                        {
                            //Import the RSA Key information. This needs
                            //to include the private key information.
                            RSA.ImportParameters(RSAKeyInfo);

                            //Decrypt the passed byte array and specify OAEP padding.  
                            //OAEP padding is only available on Microsoft Windows XP or
                            //later.  
                            algoritmo.Key = RSA.Decrypt(srKey.ReadBytes(128), DoOAEPPadding);
                            algoritmo.IV = RSA.Decrypt(srKey.ReadBytes(128), DoOAEPPadding);
                        }
                    }

                }

                ICryptoTransform decryptor = algoritmo.CreateDecryptor(algoritmo.Key, algoritmo.IV);

                int lenght = data.Length - 256;
                using (MemoryStream streamTextoEncriptado = new MemoryStream(data, 256, lenght))
                {
                    using (CryptoStream csStream = new CryptoStream(streamTextoEncriptado, decryptor, CryptoStreamMode.Read))
                    {
                        using (BinaryReader reader = new BinaryReader(csStream))
                        {
                            return UTF8Encoding.UTF8.GetString(reader.ReadBytes(lenght));
                        }
                    }
                }
            }
        }
        private void button2_Click(object sender, EventArgs e)
        {
            var key = new RSAParameters()
            {
                D = new byte[] { 9, 162, 25, 165, 196, 78, 187, 124, 249, 9, 107, 119, 251, 240, 23, 20, 100, 5, 233, 167, 17, 96, 120, 39, 136, 172, 40, 29, 14, 33, 18, 110, 89, 0, 160, 61, 129, 208, 187, 20, 200, 123, 24, 128, 233, 33, 114, 138, 136, 179, 17, 75, 62, 2, 172, 102, 177, 109, 165, 166, 215, 126, 47, 55, 7, 78, 60, 241, 46, 128, 143, 213, 156, 170, 121, 253, 105, 26, 95, 6, 143, 4, 27, 196, 154, 83, 145, 175, 36, 243, 89, 188, 79, 169, 197, 118, 51, 41, 42, 193, 32, 18, 129, 45, 214, 203, 40, 245, 190, 106, 186, 206, 172, 41, 68, 208, 251, 220, 210, 73, 36, 209, 211, 73, 225, 166, 11, 189 },
                DP = new byte[] { 23, 10, 77, 114, 154, 63, 146, 58, 61, 0, 73, 222, 175, 42, 38, 117, 16, 132, 102, 81, 16, 190, 140, 25, 137, 38, 104, 9, 4, 64, 78, 144, 32, 43, 28, 150, 117, 59, 171, 19, 94, 179, 155, 180, 216, 246, 14, 107, 72, 35, 245, 138, 49, 62, 214, 2, 71, 244, 137, 253, 205, 17, 70, 43 },
                DQ = new byte[] { 244, 207, 137, 183, 45, 246, 208, 48, 77, 221, 226, 209, 2, 16, 199, 10, 117, 155, 64, 17, 226, 253, 47, 43, 195, 17, 206, 108, 101, 152, 229, 10, 1, 22, 182, 130, 236, 83, 141, 50, 218, 176, 35, 98, 34, 145, 86, 152, 55, 158, 156, 204, 247, 184, 122, 73, 255, 243, 46, 201, 64, 1, 149, 93 },
                Exponent = new byte[] { 1, 0, 1 },
                InverseQ = new byte[] { 166, 101, 146, 7, 247, 97, 5, 116, 28, 229, 39, 17, 174, 58, 253, 123, 55, 174, 168, 164, 74, 108, 231, 233, 201, 230, 242, 131, 238, 204, 208, 45, 152, 229, 97, 154, 208, 119, 206, 244, 211, 14, 46, 39, 79, 52, 190, 202, 134, 0, 245, 15, 14, 175, 54, 5, 178, 234, 6, 224, 3, 165, 4, 152 },
                Modulus = new byte[] { 199, 209, 235, 83, 229, 243, 67, 47, 206, 155, 52, 106, 107, 93, 98, 30, 204, 74, 49, 108, 137, 56, 59, 245, 136, 159, 216, 142, 201, 91, 206, 135, 6, 8, 197, 58, 15, 43, 201, 47, 248, 220, 37, 28, 53, 46, 133, 197, 132, 227, 215, 214, 34, 109, 210, 167, 202, 58, 5, 78, 103, 100, 0, 151, 100, 142, 8, 61, 54, 153, 171, 232, 90, 28, 184, 202, 190, 21, 103, 23, 180, 178, 115, 201, 177, 85, 250, 215, 61, 164, 164, 47, 64, 17, 131, 162, 48, 137, 60, 255, 116, 85, 137, 134, 33, 201, 32, 242, 255, 249, 149, 184, 129, 235, 62, 16, 222, 102, 39, 43, 222, 46, 75, 114, 74, 249, 159, 151 },
                P = new byte[] { 202, 181, 209, 127, 134, 141, 138, 46, 235, 57, 222, 160, 241, 37, 211, 58, 37, 236, 59, 182, 37, 184, 192, 117, 77, 162, 20, 206, 124, 169, 11, 135, 31, 54, 162, 156, 40, 89, 234, 45, 161, 187, 1, 73, 136, 181, 111, 197, 240, 95, 12, 87, 204, 229, 175, 0, 61, 69, 45, 210, 172, 2, 114, 187 },
                Q = new byte[] { 252, 89, 151, 105, 46, 192, 98, 218, 208, 204, 90, 225, 163, 202, 231, 52, 178, 126, 52, 116, 30, 190, 21, 65, 111, 118, 167, 141, 13, 75, 240, 37, 182, 108, 65, 39, 183, 115, 226, 104, 46, 76, 240, 58, 182, 202, 213, 189, 127, 217, 43, 149, 196, 107, 255, 155, 121, 199, 29, 227, 238, 54, 222, 213 }
            };
            File.WriteAllText(@"E:\PacoteExtraçãoCompleto.decr", Decrypt(File.ReadAllText(@"E:\PacoteExtraçãoCompleto.encr"), key, false));

        }

        private void Print(StringBuilder sb, byte[] array, bool comma)
        {
            bool first = true;
            foreach (var item in array)
            {
                if (first)
                    first = false;
                else
                    sb.Append(", ");
                sb.Append((int)item);
            }
            if (comma)
                sb.AppendLine("},");
            else
                sb.AppendLine("}");
        }

        private void button3_Click(object sender, EventArgs e)
        {
            
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                //Import the RSA Key information. This needs
                //to include the private key information.
                var key = RSA.ExportParameters(true);

                StringBuilder sb = new StringBuilder();
                sb.AppendLine(@"var key = new RSAParameters()
            {
                D = new byte[] { "); Print(sb, key.D, true);
                sb.AppendLine("DP = new byte[] {");Print(sb, key.DP, true);
                sb.AppendLine("DQ = new byte[] { "); Print(sb, key.DQ, true);
                sb.AppendLine("Exponent = new byte[] { "); Print(sb, key.Exponent, true);
                sb.AppendLine("InverseQ = new byte[] { "); Print(sb, key.InverseQ, true);
                sb.AppendLine("Modulus = new byte[] { "); Print(sb, key.Modulus, true);
                sb.AppendLine("P = new byte[] { "); Print(sb, key.P, true);
                sb.AppendLine("Q = new byte[] { "); Print(sb, key.Q, false);
                sb.AppendLine("};");

                textBox2.Text = sb.ToString();
                
            }
        }
    }
}
