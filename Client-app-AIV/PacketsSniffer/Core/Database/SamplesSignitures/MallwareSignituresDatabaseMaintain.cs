using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MySql.Data.MySqlClient;

namespace PacketsSniffer.Core.Database.SamplesSignitures
{
    //class MallwareSignituresDatabaseMaintain
    //{
    //    private readonly string _connectionString;//LOCAL IMAGE MYSQL
    //    public MallwareSignituresDatabaseMaintain()
    //    {
    //        _connectionString = "Server=127.0.0.1;port=3456;database=Samples;uid=root;pwd=my-secret-pw;";
    //    }

    //    // insert malware hashes from the database
    //    private void InsertMalwareHashes()
    //    {
    //        var hashes = new List<string>();
    //        using (var connection = new MySqlConnection(_connectionString))
    //        {
    //            connection.Open();
    //            var query = "SELECT Sha256 FROM Hashes";
    //            using (var command = new MySqlCommand(query, connection))
    //            {
    //                using (var reader = command.ExecuteReader())
    //                {
    //                    while (reader.Read())
    //                    {
    //                        hashes.Add(reader.GetString(0)); // Read the Sha256 column
    //                    }
    //                }
    //            }
    //        }
    //    }
    //}
}
