using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class AuthorizationRequestConfiguration : IEntityTypeConfiguration<AuthorizationRequest>
{
    public void Configure(EntityTypeBuilder<AuthorizationRequest> builder)
    {
        builder.ToTable("authorization_requests", t =>
        {
            t.HasCheckConstraint("ck_authorization_requests_max_age", "max_age_seconds IS NULL OR max_age_seconds >= 0");
            t.HasCheckConstraint(
                "ck_authorization_requests_consent",
                "(consent_user_id IS NULL) = (consent_approved IS NULL)");
            t.HasCheckConstraint(
                "ck_authorization_requests_selection",
                "(selected_sid IS NULL) = (selected_at IS NULL) AND (selected_sid IS NULL OR length(selected_sid) = 22)");
            t.HasCheckConstraint(
                "ck_authorization_requests_dpop_key",
                "dpop_key_thumbprint IS NULL OR length(dpop_key_thumbprint) = 43");
        });

        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id).ValueGeneratedNever();
        builder.HasOne<Tenant>().WithMany().HasForeignKey(r => r.TenantId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<Client>().WithMany().HasForeignKey(r => r.ClientPk).OnDelete(DeleteBehavior.Cascade);

        builder.Property(r => r.RedirectUri).HasMaxLength(2048).IsRequired();
        builder.Property(r => r.Scope).HasMaxLength(1024).IsRequired();
        builder.Property(r => r.State).HasMaxLength(AuthorizationRequest.MaxClientValueLength);
        builder.Property(r => r.Nonce).HasMaxLength(AuthorizationRequest.MaxClientValueLength);

        // code_challenge_method is always S256, so it has no column (D2).
        builder.Property(r => r.CodeChallenge).HasMaxLength(43).IsFixedLength().IsRequired();
        builder.Property(r => r.ForceLogin);
        builder.Property(r => r.MaxAge).HasColumnName("max_age_seconds").HasConversion(Converters.Seconds);
        builder.Property(r => r.CreatedAt);
        builder.Property(r => r.ExpiresAt);
        builder.Property(r => r.ConsentUserId);
        builder.Property(r => r.ConsentApproved);
        builder.Property(r => r.DpopKeyThumbprint).HasMaxLength(43);
        builder.Property(r => r.PromptNone);
        builder.Property(r => r.ForceConsent);

        // The account choice (#41, D51 to D53).
        builder.Property(r => r.SelectAccount);
        builder.Property(r => r.LoginHint).HasMaxLength(AuthorizationRequest.MaxLoginHintLength);
        builder.Property(r => r.HintUserId);
        builder.Property(r => r.SelectedSid).HasMaxLength(22);
        builder.Property(r => r.SelectedAt);

        // D41, D42: /authorize finds a pushed request by the hash of its request_uri. Unique, so one value can never
        // match two rows. The plain request_uri is never stored (D3).
        builder.Property(r => r.RequestUriHash).HasConversion(Converters.Hash).HasMaxLength(32);
        builder.HasIndex(r => new { r.TenantId, r.RequestUriHash }).IsUnique().HasFilter("request_uri_hash IS NOT NULL");

        // The purge job deletes expired requests.
        builder.HasIndex(r => r.ExpiresAt);
    }
}
