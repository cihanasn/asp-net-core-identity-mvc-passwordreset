using Microsoft.EntityFrameworkCore.Migrations;

namespace asp_net_core_identity_mvc.Migrations
{
    public partial class AddRoles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "d005c076-3861-4102-bd76-5b7373c89fed", "6f9e5003-07de-4cb5-87da-c5465b502132", "User", "USER" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "cad2d391-3a71-4eed-899f-fe5c8b0fee8a", "1daea930-d902-4f60-a720-9379acea2b87", "Admin", "ADMIN" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "cad2d391-3a71-4eed-899f-fe5c8b0fee8a");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "d005c076-3861-4102-bd76-5b7373c89fed");
        }
    }
}
