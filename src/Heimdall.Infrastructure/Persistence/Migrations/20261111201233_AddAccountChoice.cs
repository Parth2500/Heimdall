using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAccountChoice : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "hint_user_id",
                table: "authorization_requests",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "login_hint",
                table: "authorization_requests",
                type: "character varying(254)",
                maxLength: 254,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "select_account",
                table: "authorization_requests",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "selected_at",
                table: "authorization_requests",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "selected_sid",
                table: "authorization_requests",
                type: "character varying(22)",
                maxLength: 22,
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_authorization_requests_selection",
                table: "authorization_requests",
                sql: "(selected_sid IS NULL) = (selected_at IS NULL) AND (selected_sid IS NULL OR length(selected_sid) = 22)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_authorization_requests_selection",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "hint_user_id",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "login_hint",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "select_account",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "selected_at",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "selected_sid",
                table: "authorization_requests");
        }
    }
}
