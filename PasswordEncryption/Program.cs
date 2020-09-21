using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace PasswordEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            Dictionary<string, string> credentials = new Dictionary<string, string>();
            int inputChoice = 0;

            do
            {
                Console.WriteLine("\n------------------------------------------\n");
                Console.WriteLine("PASSWORD AUTHENTICATION SYSTEM\n\n");
                Console.WriteLine("Please select an option:");
                Console.WriteLine("1. Establish an account");
                Console.WriteLine("2. Authenticate a user");
                Console.WriteLine("3. Exit the application\n\n");
                Console.Write("Enter selection: ");
                inputChoice = Int32.Parse(Console.ReadLine());
                Console.WriteLine("\n------------------------------------------\n\n");

                if (inputChoice == 1)
                {
                    Signup(credentials);
                }
                else if (inputChoice == 2)
                {
                    Signin(credentials);
                }

                
            }
            while (inputChoice != 3);
        }

        private static void Signup(Dictionary<string, string> credentials)
        {
            Console.WriteLine("Enter a username: ");
            string username = Console.ReadLine();
            Console.WriteLine("Enter a password: ");
            string password = Console.ReadLine();
            string hashed = Hasher(password);
            credentials.Add(username, hashed);
        }

        private static void Signin(Dictionary<string, string> credentials)
        {
            Console.WriteLine("Enter your username: ");
            string username = Console.ReadLine();

            if (!credentials.ContainsKey(username))
            {
                Console.WriteLine("*** That username does not exist ***");
                return;
            }

            Console.WriteLine("Enter your password: ");
            string password = Hasher(Console.ReadLine());

            if (!(password == credentials[username]))
            {
                Console.WriteLine("*** The password you entered is incorrect ***");
                return;
            }
            Console.WriteLine("You successfully logged in");
            Console.ReadKey();
        }

        private static string Hasher(string password)
        {
            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: new byte[0],
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 1000,
                numBytesRequested: 256 / 8));
            return hashed;
        }
    }
}
