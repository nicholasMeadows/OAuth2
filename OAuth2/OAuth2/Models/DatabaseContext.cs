using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MySql.Data.MySqlClient;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace OAuth2.Models
{
    public static class DatabaseContext
    {
        private static MySqlConnection connection;
        private static string server = "98.179.199.29";
        private static string database = "oauth2";
        private static string UID = "oauth2User";
        private static string password = "oauth2User";
        private static string connectionString = "SERVER=" + server + ";" +
                                "DATABASE=" + database + ";" +
                                "UID=" + UID + ";" +
                                "PASSWORD=" + password + ";";

        public static bool ValidateUser(string username, string password) {
            connection = new MySqlConnection(connectionString);
            connection.Open();
            MySqlCommand query = new MySqlCommand("SELECT * FROM `oauth2`.`users` WHERE username = @username", connection);

            query.Parameters.Add("@username", MySqlDbType.VarChar).Value = username;

            MySqlDataReader reader = query.ExecuteReader();
            reader.Read();

            if (reader.HasRows)
            {
                string hashFromDatabase = (string)reader["hash"];
                byte[] salt = (byte[])reader["salt"];

                reader.Close();

                string hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

                if (hashFromDatabase.Equals(hash))
                    return true;
            }
            return false;
        }

        public static void RegisterUser(string username, string password)
        {
            //generate a 128-bit salt using a secure PRNG
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            
            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            string hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            connection = new MySqlConnection(connectionString);
            connection.Open();

            MySqlCommand query = new MySqlCommand("INSERT INTO `oauth2`.`users` (`username`, `hash`, `salt`) VALUES (@username, @hash, @salt);", connection);
            query.Parameters.Add("@username", MySqlDbType.VarChar).Value = username;
            query.Parameters.Add("@hash", MySqlDbType.VarChar).Value = hash;
            query.Parameters.Add("@salt", MySqlDbType.Blob).Value = salt;

            query.ExecuteNonQuery();
        }
        public static string ValidateParams(ParamModel param) {
            if (param.client_id == null)
            {
                return "Missing parameter client_id";
            }
            else if (param.redirect_uri == null)
            {
                return "Missing parameter redirect_uri";
            }
            else if (param.response_type == null)
            {
                return "Missing parameter response_type";
            }
            else if (!param.response_type.Equals("code")) {
                return "Invalid response_type";
            }



            string client_id = param.client_id;
            string response_type = param.response_type;
            string redirect_uri = param.redirect_uri;

            connection = new MySqlConnection(connectionString);
            connection.Open();
            MySqlCommand client_idQuery = new MySqlCommand("SELECT client_id FROM oauth2.client_info WHERE client_id = @client_id;", connection);
            client_idQuery.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = client_id;
            MySqlDataReader reader= client_idQuery.ExecuteReader();
            reader.Read();

            if (!reader.HasRows)
            {
                reader.Close();
                connection.Close();
                return "invalid client_id";
            }

            reader.Close();
            
            //check redirect_uri
            MySqlCommand redirect_uriQuery = new MySqlCommand("SELECT * FROM oauth2.redirect_urls WHERE client_id = @client_id AND redirect_uri = @redirect_uri;", connection);
            redirect_uriQuery.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = client_id;
            redirect_uriQuery.Parameters.Add("@redirect_uri", MySqlDbType.VarChar).Value = redirect_uri;
            reader = redirect_uriQuery.ExecuteReader();
            reader.Read();

            if (!reader.HasRows) {
                return "Illegal redirect_uri";
            }

            return "Valid";

        }

        public static string GenerateToken()
        {
            char[] token = new char[187];
            Random rand = new Random();

            for (int i = 0; i < 187; ++i)
            {
                int charAsNum = rand.Next(45, 122);

                while (charAsNum >= 58 && charAsNum <= 64 || charAsNum >= 91 && charAsNum <= 94 || charAsNum == 96 || charAsNum >= 46 && charAsNum <= 47)
                {
                    charAsNum = rand.Next(48, 122);
                }
                token[i] = (char)charAsNum;
            }

            return new string(token);
        }
    }
}
