﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MySql.Data.MySqlClient;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Text;

namespace OAuth2.Models
{
    public static class DatabaseContext
    {
        private static MySqlConnection connection;
        private static string server = "98.179.199.29";
        private static string database = "oauth2";
        private static string UID = "oauth2User";
        private static string dbPassword = "oauth2User";
        private static string connectionString = "SERVER=" + server + ";" +
                                "DATABASE=" + database + ";" +
                                "UID=" + UID + ";" +
                                "PASSWORD=" + dbPassword + ";";

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

        public static void RegisterUser(RegisterUserModel registerUserModel)
        {
            //generate a 128-bit salt using a secure PRNG
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            
            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            string hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: registerUserModel.password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            connection = new MySqlConnection(connectionString);
            connection.Open();

            MySqlCommand query = new MySqlCommand("INSERT INTO `oauth2`.`users` (`username`, `hash`, `salt`) VALUES (@username, @hash, @salt);", connection);
            query.Parameters.Add("@username", MySqlDbType.VarChar).Value = registerUserModel.username; 
            query.Parameters.Add("@hash", MySqlDbType.VarChar).Value = hash;
            query.Parameters.Add("@salt", MySqlDbType.Blob).Value = salt;

            query.ExecuteNonQuery();
            connection.Close();
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

        public static string ValidateAccessParams(AccessTokenParams param, string authorization) {
            string client_id;
            string client_secret;

            if (authorization == null)
            {
                if (param.client_id == null || param.client_secret == null)
                {
                    return "Missing client";
                }
                else
                {
                    client_id = param.client_id;
                    client_secret = param.client_secret;
                }
            }
            else{
                authorization = authorization.Substring(6);
                byte[] data = Convert.FromBase64String(authorization);
                string[] decodedAuth = Encoding.UTF8.GetString(data).Split(':');
                client_id = decodedAuth[0];
                client_secret = decodedAuth[1];
                param.client_id = client_id;
                param.client_secret = client_secret;
            }

            //Validate client id and client_secret
            connection = new MySqlConnection(connectionString);
            connection.Open();

            //check client_id and client_secret
            MySqlCommand clientId_SecretCheck = new MySqlCommand("SELECT * FROM `oauth2`.`client_info` WHERE client_id = @client_id AND client_secret = @client_secret", connection);
            clientId_SecretCheck.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = client_id;
            clientId_SecretCheck.Parameters.Add("@client_secret", MySqlDbType.VarChar).Value = client_secret;
            MySqlDataReader reader = clientId_SecretCheck.ExecuteReader();
            reader.Read();

            if (!reader.HasRows)
            {
                reader.Close();
                connection.Close();
                return "Illegal client";
            }
            reader.Close();


            if (param.grant_type == null)
            {
                return "Missing grant_type";
            }            
            else if (param.grant_type.Equals("refresh_token"))
            {
                if (param.refresh_token == null)
                {
                    return "Missing refresh_token";
                }

                //validate refreshtoken
                MySqlCommand checkRefreshToken = new MySqlCommand("SELECT * FROM `oauth2`.`access_tokens` WHERE client_id = @client_id AND refresh_token = @refresh_token", connection);
                checkRefreshToken.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = client_id;
                checkRefreshToken.Parameters.Add("@refresh_token", MySqlDbType.VarChar).Value = param.refresh_token;
                reader = checkRefreshToken.ExecuteReader();
                reader.Read();

                if (!reader.HasRows)
                {
                    return "Illegal refresh_token";
                }

                
                return "Refresh";
            }
            else if (param.grant_type.Equals("authorization_code")) {

                if (param.code == null)
                {
                    return "Missing code";
                }

                if (param.redirect_uri == null)
                {
                    return "Missing redirect_uri";
                }

                //Validate to database
                //Check valid request code
                MySqlCommand checkCode = new MySqlCommand("SELECT * FROM `oauth2`.`request_tokens` WHERE client_id = @client_id AND request_token = @request_token;", connection);
                checkCode.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = client_id;
                checkCode.Parameters.Add("@request_token", MySqlDbType.VarChar).Value = param.code;
                reader = checkCode.ExecuteReader();
                reader.Read();

                if (!reader.HasRows) {
                    reader.Close();
                    connection.Close();
                    return "Illegal code";
                }
                reader.Close();

                //Check valid redirect uri
                MySqlCommand checkRedirect = new MySqlCommand("SELECT * FROM `oauth2`.`redirect_urls` WHERE client_id = @client_id AND redirect_uri = @redirect_uri", connection);
                checkRedirect.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = client_id;
                checkRedirect.Parameters.Add("@redirect_uri", MySqlDbType.VarChar).Value = param.redirect_uri;
                reader = checkRedirect.ExecuteReader();
                reader.Read();

                if (!reader.HasRows) {
                    reader.Close();
                    connection.Close();
                    return "Illegal redirect_uri";        
                }
                reader.Close();
                connection.Close();
                return "Access";
            }
            else if (!param.grant_type.Equals("refresh_token") || !param.grant_type.Equals("access_token"))
            {
                return "Illegal grant_type";
            }
            return "Valid";
        }

        public static string GenerateToken(string client_id)
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

            connection = new MySqlConnection(connectionString);
            connection.Open();
            MySqlCommand query = new MySqlCommand("INSERT INTO `oauth2`.`request_tokens` (client_id, request_token, time_stamp) VALUES (@client_id, @request_token, CURRENT_TIMESTAMP())", connection);

            query.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = client_id;
            query.Parameters.Add("@request_token", MySqlDbType.VarChar).Value = new string (token);

            query.ExecuteNonQuery();
            connection.Close();
            
            return new string(token);
        }


        public static AccessTokenModel GenerateAccessToken(string client_id)
        {

            char[] accessToken = new char[151];
            Random rand = new Random();

            for (int i = 0; i < 151; ++i)
            {
                int charAsNum = rand.Next(45, 122);

                while (charAsNum >= 58 && charAsNum <= 64 || charAsNum >= 91 && charAsNum <= 94 || charAsNum == 96 || charAsNum >= 46 && charAsNum <= 47)
                {
                    charAsNum = rand.Next(48, 122);
                }
                accessToken[i] = (char)charAsNum;
            }


            char[] refreshToken = new char[131];
            

            for (int i = 0; i < 131; ++i)
            {
                int charAsNum = rand.Next(45, 122);

                while (charAsNum >= 58 && charAsNum <= 64 || charAsNum >= 91 && charAsNum <= 94 || charAsNum == 96 || charAsNum >= 46 && charAsNum <= 47)
                {
                    charAsNum = rand.Next(48, 122);
                }
                refreshToken[i] = (char)charAsNum;
            }


            AccessTokenModel token = new AccessTokenModel();
            token.access_token = new string(accessToken);
            token.expires_id = 3600;
            token.refresh_token = new string(refreshToken);
            token.scope = "";
            token.token_type = "Bearer";


            connection = new MySqlConnection(connectionString);
            connection.Open();
            MySqlCommand query = new MySqlCommand("INSERT INTO `oauth2`.`access_tokens` (client_id, access_token, refresh_token, timestamp) VALUES (@client_id, @access_token, @refresh_token, CURRENT_TIMESTAMP);", connection);
            query.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = client_id;
            query.Parameters.Add("@access_token", MySqlDbType.VarChar).Value = token.access_token;
            query.Parameters.Add("@refresh_token", MySqlDbType.VarChar).Value = token.refresh_token;

            query.ExecuteNonQuery();
            connection.Close();
            return token;
        }

        public static RefreshTokenModel RefreshToken(string refresh_token, AccessTokenParams param)
        {
            //get required info to update db table

            connection = new MySqlConnection(connectionString);
            connection.Open();
            MySqlCommand accessInfo = new MySqlCommand("SELECT * FROM `oauth2`.`access_tokens` where refresh_token = @refresh_token AND client_id = @client_id;", connection);
            accessInfo.Parameters.Add("@refresh_token", MySqlDbType.VarChar).Value = refresh_token;
            accessInfo.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = param.client_id;

            MySqlDataReader reader = accessInfo.ExecuteReader();
            reader.Read();

            string access_token = (string)reader["access_token"];
            DateTime timestamp = (DateTime)reader["timestamp"];
            DateTime now = DateTime.Now;

            TimeSpan span = now.Subtract(timestamp);

            if (span.Hours >= 1)
            {

                char[] accessToken = new char[151];
                Random rand = new Random();

                for (int i = 0; i < 151; ++i)
                {
                    int charAsNum = rand.Next(45, 122);

                    while (charAsNum >= 58 && charAsNum <= 64 || charAsNum >= 91 && charAsNum <= 94 || charAsNum == 96 || charAsNum >= 46 && charAsNum <= 47)
                    {
                        charAsNum = rand.Next(48, 122);
                    }
                    accessToken[i] = (char)charAsNum;
                }

                reader.Close();
                MySqlCommand updateAccessToken = new MySqlCommand("UPDATE oauth2.access_tokens SET access_token = @access_token, timestamp = CURRENT_TIMESTAMP WHERE client_id = @client_id AND refresh_token = @refresh_token;", connection);
                updateAccessToken.Parameters.Add("@access_token", MySqlDbType.VarChar).Value = new string(accessToken);
                updateAccessToken.Parameters.Add("@client_id", MySqlDbType.VarChar).Value = param.client_id;
                updateAccessToken.Parameters.Add("@refresh_token", MySqlDbType.VarChar).Value = refresh_token;

                updateAccessToken.ExecuteNonQuery();
                connection.Close();

                RefreshTokenModel token = new RefreshTokenModel();
                token.access_token = new string(accessToken);
                token.expires_id = 3600;
                token.scope = "";
                token.token_type = "Bearer";

                return token;
            }
            else {
                RefreshTokenModel token = new RefreshTokenModel();
                token.access_token = access_token;
                token.expires_id = 3600;
                token.scope = "";
                token.token_type = "Bearer";

                return token;
            }

        }
    }
}
