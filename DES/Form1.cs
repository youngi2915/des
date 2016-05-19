using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Collections;
using System.Diagnostics;


namespace DES
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        //암호화 버튼 이벤트 핸들러
        private void button1_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textBox1.Text))  //암호화할게없다
            {
                return;
            }
            else  //암호화진행
            {
                //먼저 평문 textBox 내용을 가져와 파일에 저장
                FileStream Input_file = new FileStream("plaintext", FileMode.Create, FileAccess.Write);
                byte[] data = Encoding.Unicode.GetBytes(textBox1.Text);
                Input_file.Seek(0, SeekOrigin.Begin);
                Input_file.Write(data, 0, data.Length);
                Input_file.Close();

                byte[] Key = new byte[8];

                if(string.IsNullOrWhiteSpace(textBox2.Text))    //Key가 입력되지 않음
                {
                    //
                    return;
                }

                else
                {   
                    byte[] tmp = Encoding.Unicode.GetBytes(textBox2.Text);

                    //if (tmp.Length < 8)
                    //{
                    //    for(int i=0; i<tmp.Length; i++)
                    //    {
                    //        Key[i] = tmp[i];
                    //    }
                    //}
                    //else
                    //{
                    //    for (int i = 0; i < 8; i++)
                    //    {
                    //        Key[i] = tmp[i];
                    //    }
                    //}

                    for(int i=0; i<8 && i<tmp.Length; i++)
                    {
                        Key[i] = tmp[i];
                    }
                }

                //암호화
                DES des = new DES();
                des.Set_If_Encryption(true);
                des.Encryption(Key);

                //암호문을 파일에서 읽어와 암호문 textBox에 출력
                FileStream Output_file = new FileStream("ciphertext", FileMode.Open, FileAccess.Read);
                byte[] data2 = new byte[(int)Output_file.Length];
                Output_file.Read(data2, 0, (int)Output_file.Length);
                Output_file.Close();
                textBox3.Text = Encoding.Unicode.GetString(data2);
            }
        }

        //복호화 버튼 이벤트 핸들러
        private void button2_Click(object sender, EventArgs e)
        {
            DES des = new DES();
            des.Set_If_Encryption(false);
            des.Decryption();

            FileStream Output_file = new FileStream("ciphertext_decryption", FileMode.Open, FileAccess.Read);
            byte[] data = new byte[(int)Output_file.Length];
            Output_file.Read(data, 0, (int)Output_file.Length);
            Output_file.Close();
            textBox4.Text = Encoding.Unicode.GetString(data);
        }
    }

    public class DES
    {      
        private int[] Initial_Permutation = { 58, 50, 42, 34, 26, 18, 10, 02, 60, 52, 44, 36, 28, 20, 12, 04, 62, 54, 46, 38, 30, 22, 14, 06, 64, 56, 48, 40, 32, 24, 16, 08, 57, 49, 41, 33, 25, 17, 09, 01, 59, 51, 43, 35, 27, 19, 11, 03, 61, 53, 45, 37, 29, 21, 13, 05, 63, 55, 47, 39, 31, 23, 15, 07 };
        private int[] Final_Parmutation = { 40, 08, 48, 16, 56, 24, 64, 32, 39, 07, 47, 15, 55, 23, 63, 31, 38, 06, 46, 14, 54, 22, 62, 30, 37, 05, 45, 13, 53, 21, 61, 29, 36, 04, 44, 12, 52, 20, 60, 28, 35, 03, 43, 11, 51, 19, 5, 27, 34, 02, 42, 10, 50, 18, 58, 26, 33, 01, 41, 09, 49, 17, 57, 25 };
        private int[,] S_Box = { { 14, 04, 13, 01, 02, 15, 11, 08, 03, 10, 06, 12, 05, 09, 00, 07 }, { 00, 15, 07, 04, 14, 02, 13, 10, 03, 06, 12, 11, 09, 05, 03, 08 }, { 04, 01, 14, 08, 13, 06, 02, 11, 15, 12, 09, 07, 03, 10, 05, 00 }, { 15, 12, 08, 02, 04, 09, 01, 07, 05, 11, 03, 14, 10, 00, 06, 13 } };
        private int[] Expansion_P_Box = { 32, 01, 02, 03, 04, 05, 04, 05, 06, 07, 08, 09, 08, 09, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 23, 25, 24, 25, 26, 27, 28, 29, 28, 29, 31, 31, 32, 01};
        private int[] Straight_P_Box = { 16, 07, 20, 21, 29, 12, 28, 17, 01, 15, 23, 26, 05, 18, 31, 10, 02, 08, 24, 14, 32, 27, 03, 09, 19, 13, 30, 06, 22, 11, 04, 25 };
        private int[] Parity_Drop = { 57, 49, 41, 33, 25, 17, 09, 01, 58, 50, 42, 34, 26, 18, 10, 02, 59, 51, 43, 35, 27, 19, 11, 03, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 07, 62, 54, 46, 38, 30, 22, 14, 06, 61, 53, 45, 37, 29, 21, 13, 05, 28, 20, 12, 04};
        private int[] Key_generate_shift = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        private int[] Key_compression = { 14, 17, 11, 24, 01, 05, 03, 28, 15, 06, 21, 10, 23, 19, 12, 04, 26, 08, 16, 07, 27, 20, 13, 02, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

        private static byte[][] Keys=new byte[16][];

        private int round_count;
        private bool if_encryption;

        private static bool encoded;

        public DES()
        {
            for (int i = 0; i < 16; i++)
                Keys[i] = new byte[6];
        }

        public void Set_encoded(bool input)
        {
            encoded = input;
        }

        public bool Get_encoded()
        {
            return encoded;
        }

        public void Set_If_Encryption(bool input)
        {
            if_encryption = input;
            return;
        }

        public void Encryption(byte[] KeyInput)
        {
            //1~16 Round Key Generate
            Key_Generate(KeyInput);

            //입력파일 열어서 읽기
            FileStream Input = new FileStream("plaintext", FileMode.Open, FileAccess.Read);
            byte[] data = new byte[Input.Length];
            Input.Read(data, 0, (int)Input.Length);

            Debug.WriteLine(Input.Length);

            //8바이트씩(64bit씩) 몇번 반복해야 하는가
            int how_long = ((int)Input.Length) / 8;

            //암호화 한 결과 txt를 저장할 파일 스트림
            FileStream Output = new FileStream("ciphertext", FileMode.Create, FileAccess.Write);
            Output.Seek(0, SeekOrigin.Begin);
            
            byte[] byte_8;

            for (int i = 0; i <= how_long; i++)
            {
                byte_8 = new byte[8];

                if (i == how_long)
                {
                    int rest = data.Length - 8 * how_long;
                    if (rest == 0)
                    {
                        Input.Close();
                        Output.Close();
                        return;
                        //continue;
                    }
                    for (int j = 0; j < rest; j++)
                    {
                        byte_8[j] = data[8 * i + j];
                    }
                    for (int j = rest; j < 8; j++)
                    {
                        byte_8[j] = 0;
                    }
                }
                else
                {
                    byte_8[0] = data[8 * i];
                    byte_8[1] = data[8 * i + 1];
                    byte_8[2] = data[8 * i + 2];
                    byte_8[3] = data[8 * i + 3];
                    byte_8[4] = data[8 * i + 4];
                    byte_8[5] = data[8 * i + 5];
                    byte_8[6] = data[8 * i + 6];
                    byte_8[7] = data[8 * i + 7];
                }

                BitArray bits_64 = new BitArray(byte_8);

            

                //초기 치환
                bits_64 = Parmutation(bits_64, true);

                //Debug.WriteLine("초기치환후 : " + bits_64.Length);

                //Round 1~16
                round_count = 0;

                for (int k = 0; k < 16; k++)
                {
                    bits_64 = Round(bits_64);
                    round_count++;
                }

                //Debug.WriteLine("Round 후 : " + bits_64.Length);

                //최종 치환
                bits_64 = Parmutation(bits_64, false);

                //Debug.WriteLine("최종치환후 : " + bits_64.Length);

                //파일에 씀
                bits_64.CopyTo(byte_8, 0);

                //Debug.WriteLine("바이트변환 : " + byte_8.Length);

                Output.Write(byte_8, 0, byte_8.Length);
                //Debug.WriteLine("여기옴");
                //Debug.WriteLine("Output.Length=" + Output.Length);
            }

            Input.Close();
            Output.Close();

            return;
        }

        public void Decryption()
        {

            Debug.WriteLine("///////////////////");
            //입력파일 열어서 읽기
            FileStream Input = new FileStream("ciphertext", FileMode.Open, FileAccess.Read);
            byte[] data = new byte[Input.Length];
            Input.Read(data, 0, (int)Input.Length);

            //8바이트씩(64bit씩) 몇번 반복해야 하는가
            int how_long = ((int)Input.Length) / 8;

            Debug.WriteLine(how_long);

            //암호화 한 결과 txt를 저장할 파일 스트림
            FileStream Output = new FileStream("ciphertext_decryption", FileMode.Create, FileAccess.Write);
            Output.Seek(0, SeekOrigin.Begin);

            byte[] byte_8;

            for (int i = 0; i <= how_long; i++)
            {
                byte_8 = new byte[8];

                if (i == how_long)
                {
                    int rest = data.Length - 8 * how_long;
                    if (rest == 0)
                    {
                        Input.Close();
                        Output.Close();
                        return;
                        //continue;
                    }
                    for (int j = 0; j < rest; j++)
                    {
                        byte_8[j] = data[8 * i + j];
                    }
                    for(int j=rest; j < 8; j++ )
                    {
                        byte_8[j] = 0;
                    }
                }
                else
                {
                    byte_8[0] = data[8 * i];
                    byte_8[1] = data[8 * i + 1];
                    byte_8[2] = data[8 * i + 2];
                    byte_8[3] = data[8 * i + 3];
                    byte_8[4] = data[8 * i + 4];
                    byte_8[5] = data[8 * i + 5];
                    byte_8[6] = data[8 * i + 6];
                    byte_8[7] = data[8 * i + 7];
                }

                //Debug.WriteLine("8byte출력 " + i + "번째 : " + byte_8[1]);
                BitArray bits_64 = new BitArray(byte_8);

                //초기 치환
                bits_64 = Parmutation(bits_64, true);

                //Round 1~16
                round_count = 0;

                for (int k = 0; k < 16; k++)
                {
                    bits_64 = Round(bits_64);
                    round_count++;
                }

                //최종 치환
                bits_64 = Parmutation(bits_64, false);

                //파일에 씀
                //Debug.WriteLine("bits_64.Legnth = " + bits_64.Length);
                bits_64.CopyTo(byte_8, 0);
                Output.Write(byte_8, 0, 8);
            }

            Input.Close();
            Output.Close();

            return;
        }

        private void Key_Generate(byte[] Key_Input)
        {
            BitArray input_64 = new BitArray(Key_Input);
            BitArray after_parity_drop_56 = new BitArray(56, false);
            int before = 0;

            //Debug.WriteLine("input_64.Length = " + input_64.Length);

            //for (int k = 0; k < Key_Input.Length; k++)
            //{
            //    Debug.Write(Key_Input[k].ToString() + " /// ");
            //}
            //Debug.WriteLine("");

            //parity drop
            for (int i = 0; i < 56; i++ )
            {
                before = Parity_Drop[i];

                //Debug.WriteLine("i = " + i + ", (before-1) = " + (before - 1));
                after_parity_drop_56.Set(i, input_64.Get(before - 1));
               // after_parity_drop_56[i]
            }

            //for (int k = 0; k < after_parity_drop_56.Length; k++)
            //{
            //    Debug.Write(after_parity_drop_56[k].ToString() + " /// ");
            //}
            //Debug.WriteLine("");

            BitArray Left = new BitArray(28, false);
            BitArray Right = new BitArray(28, false);
            BitArray after_compress = new BitArray(48, false);

            for (int i = 0; i < 28; i++)
            {
                Left[i] = after_parity_drop_56[i];
                Right[i] = after_parity_drop_56[i + 28];
            }

            //for (int k = 0; k < Left.Length; k++)
            //{
            //    Debug.Write(Left[k].ToString() + " /// ");
            //}
            //Debug.WriteLine("");
            //for (int k = 0; k < Right.Length; k++)
            //{
            //    Debug.Write(Right[k].ToString() + " /// ");
            //}
            //Debug.WriteLine("");

            //16번의 Key 생성
            for (int i = 0; i < 16; i++)
            {
                //Shift Left rotate
                int shift_left = Key_generate_shift[i];
                BitArray temp = new BitArray(shift_left * 2, false);

                if (shift_left == 1)
                {
                    temp[0] = Left[0];
                    temp[1] = Right[0];
                }
                else if (shift_left == 2)
                {
                    temp[0] = Left[0];
                    temp[1] = Left[1];
                    temp[2] = Right[0];
                    temp[3] = Right[1];
                }

                for (int j = 0; j < (28 - shift_left); j++)
                {

                    Left[j] = Left[j + shift_left];
                    Right[j] = Right[j + shift_left];
                }

                if (shift_left == 1)
                {
                    Left[27] = temp[0];
                    Right[27] = temp[1];
                }
                else if (shift_left == 2)
                {
                    Left[26] = temp[0];
                    Left[27] = temp[1];
                    Right[26] = temp[2];
                    Right[27] = temp[3];
                }

                //for (int k = 0; k < Left.Length; k++)
                //{
                //    Debug.Write(Left[k].ToString() + " /// ");
                //}
                //Debug.WriteLine("");
                //for (int k = 0; k < Right.Length; k++)
                //{
                //    Debug.Write(Right[k].ToString() + " /// ");
                //}
                //Debug.WriteLine("");

                //Compress P_Box
                for (int j = 0; j < 16; j++)
                {
                    before = Key_compression[j];

                    if (before < 28)
                    {
                        after_compress.Set(j, Left.Get(before - 1));
                    }
                    else
                    {
                        after_compress.Set(j, Right.Get(before - 28));
                    }

                    after_compress.CopyTo(Keys[j], 0);      // 키 배열에 저장!

                    //for (int k = 0; k < after_compress.Length; k++)
                    //{
                    //    Debug.Write(after_compress[k].ToString() + " /// ");
                    //}
                    //Debug.WriteLine("");
                }
            }

            return;
        }

        private BitArray Parmutation(BitArray input, bool if_initial)   //초기 치환, 최종 치환
        {
            int[] parmu_array;
            BitArray result = new BitArray(64, false);
            
            int before;

            if(if_initial)
            {
                parmu_array = Initial_Permutation;
            }
            else
            {
                parmu_array = Final_Parmutation;
            }

            for (int i = 0; i < 64; i++ )
            {
                before = parmu_array[i];
                if (input.Get(before - 1))
                {
                    //input의 before-1 인덱스 비트 값을 i인덱스로
                    result.Set(i, true);
                }
                else continue;  //0일필요는 바꿔줄 필요가 없음
            }

            return result;
        }

        private BitArray Round(BitArray input)     //Round
        {
            BitArray left = new BitArray(32, false);
            BitArray right = new BitArray(32, false);
            BitArray result = new BitArray(64, false);

            //Mixer
            //Left32, Right32
            for (int i = 0; i < 32; i++ )
            {
                left[i] = input[i];
                right[i] = input[i + 32];
            }

            right = Key_function(right);

            left = right.Xor(left);

            //if (round_count == 15) return result;

            //Swapper
            if (round_count == 16)
            {
                for (int i = 0; i < 32; i++)
                {
                    result[i] = left[i];
                    result[i + 32] = input[i + 32];
                }
            }
            else
            {
                for (int i = 0; i < 32; i++)
                {
                    result[i] = input[i + 32];
                    result[i + 32] = left[i];
                }
            }

            return result;
        }

        private BitArray Key_function(BitArray input)
        {
            BitArray temp = new BitArray(48, false);
            BitArray temp2 = new BitArray(32, false);
            BitArray temp3 = new BitArray(6, false);
            BitArray temp4 = new BitArray(4, false);
            BitArray result = new BitArray(32, false);
            BitArray key;

            int before;

            if (if_encryption == true)
                key = new BitArray(Keys[round_count]);
            else
                key = new BitArray(Keys[15 - round_count]);


            for (int k = 0; k < key.Length; k++)
            {
                Debug.Write(key[k].ToString() + " /// ");
            }
            Debug.WriteLine("");
    
            //Expansion_P_Box (32 -> 48 bits)
            for (int i = 0; i < 48; i++)
            {
                before = Expansion_P_Box[i];
                temp.Set(i, input.Get(before - 1));
            }

            //Xor with 48bits key
            temp = temp.Xor(key);

            //S_Boxs (48bits to 32bits)
            for (int i = 0; i < 8; i++ )
            {
                //Debug.WriteLine("temp3[0] = " + temp3[0] + ", temp[" + 6 * i + "] = " + temp[6 * i]);
                temp3[0] = temp[6 * i];
                //Debug.WriteLine("temp3[0] = " + temp3[0] + ", temp[" + 6 * i + "] = " + temp[6 * i]);
                temp3[1] = temp[6 * i + 1];
                temp3[2] = temp[6 * i + 2];
                temp3[3] = temp[6 * i + 3];
                temp3[4] = temp[6 * i + 4];
                temp3[5] = temp[6 * i + 5];

                temp4 = _S_Box(temp3);

                temp2[4 * i] = temp4[0];
                temp2[4 * i + 1] = temp4[1];
                temp2[4 * i + 2] = temp4[2];
                temp2[4 * i + 3] = temp4[3];
            }

            //Straight_P_Box
            for (int i = 0; i < 32; i++)
            {
                before = Straight_P_Box[i];
                result.Set(i, temp2.Get(before - 1));
            }

            return result;
        }

        private BitArray _S_Box(BitArray input)
        {
            int row = 0;
            int[] column = new int[1];
            int value = 0;
            BitArray temp = new BitArray(4, false);
           
            if(input.Get(0))
                row += 2;            
            if (input.Get(5))
                row += 1;

            temp[0] = input[1];
            temp[1] = input[2];
            temp[2] = input[3];
            temp[3] = input[4];

            temp.CopyTo(column, 0);
            value = S_Box[row, column[0]];

            BitArray result = new BitArray(BitConverter.GetBytes(value));

            return temp;
        }
    } 
}
