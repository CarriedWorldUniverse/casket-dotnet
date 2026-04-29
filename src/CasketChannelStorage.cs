using System.Threading;
using System.Threading.Tasks;

namespace Casket;

/// <summary>
/// Storage abstraction for channel identity key material.
/// Implement against any async k/v store (file system, Azure Key Vault, etc.).
/// </summary>
public interface ICasketChannelStorage
{
    ValueTask<string?> GetAsync(string key, CancellationToken cancellationToken = default);
    ValueTask PutAsync(string key, string value, CancellationToken cancellationToken = default);
    ValueTask DeleteAsync(string key, CancellationToken cancellationToken = default);
}
