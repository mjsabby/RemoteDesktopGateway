namespace RemoteDesktopGateway
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Sockets;
    using System.Net.WebSockets;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.WebUtilities;

    internal static class Program
    {
        public static async Task Main(string[] args)
        {
            var config = RDPGatewayConfig.Parse(await File.ReadAllTextAsync(Path.Combine(Directory.GetParent(Environment.ProcessPath).FullName, "appsettings.json")).ConfigureAwait(false));
            var authConfig = GoogleOAuthConfig.Parse(await File.ReadAllTextAsync(config.PathToGoogleOAuthClientSecretFile).ConfigureAwait(false));
            var certificateBytes = Convert.FromBase64String(await File.ReadAllTextAsync(config.PathToTLSCertificatePEM).ConfigureAwait(false));
            (var maxAge, authConfig.PublicKeys) = await GetGoogleOAuthPublicKeys(authConfig.PublicKeysUrl).ConfigureAwait(false);

            using var ctrlc = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) =>
            {
                ctrlc.Cancel();
                e.Cancel = true;
            };

            using var timer = new PeriodicTimer(maxAge);
            var timerTask = Task.Run(async () =>
            {
                while (!ctrlc.IsCancellationRequested)
                {
                    (timer.Period, authConfig.PublicKeys) = await GetGoogleOAuthPublicKeys(authConfig.PublicKeysUrl).ConfigureAwait(false);
                    await timer.WaitForNextTickAsync(ctrlc.Token).ConfigureAwait(false);
                }
            });

            var builder = WebApplication.CreateSlimBuilder(args);
            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.Listen(IPAddress.Any, config.Port, listenOptions =>
                {
                    listenOptions.UseHttps(new X509Certificate2(certificateBytes));
                });
            });

            var app = builder.Build();
            app.UseWebSockets();

            byte[] encryptionKey = GenerateAesKey(); // yes, this means that the refresh token is encrypted with a key that is generated on every startup
            using ECDsa signingKey = ECDsa.Create();
            var ec = signingKey.ExportParameters(includePrivateParameters: false);
            string x = WebEncoders.Base64UrlEncode(ec.Q.X);
            string y = WebEncoders.Base64UrlEncode(ec.Q.Y);

            app.Map("/login", async (HttpContext context, CancellationToken cancellationToken) =>
            {
                await HandleLogin(context, config, authConfig, encryptionKey, signingKey, x, y, cancellationToken).ConfigureAwait(false);
            });

            app.Map("/logout", async (HttpContext context, CancellationToken cancellationToken) =>
            {
                await HandleLogout(context, cancellationToken).ConfigureAwait(false);
            });

            app.Map("/genrdp", async (HttpContext context, CancellationToken cancellationToken) =>
            {
                await HandleGenRDP(context, config, authConfig, encryptionKey, signingKey, cancellationToken).ConfigureAwait(false);
            });

            app.Map("/remoteDesktopGateway", async (HttpContext context, CancellationToken cancellationToken) =>
            {
                await HandleRemoteDesktopGateway(context, (string idToken) => AuthenticateAndGetServerList(idToken, authConfig.PublicKeys, config.AllowedUsers, authConfig), cancellationToken).ConfigureAwait(false);
            });

            app.Map("/", async (HttpContext context, CancellationToken cancellationToken) =>
            {
                await HandleIndex(context, config, authConfig, encryptionKey, signingKey, cancellationToken).ConfigureAwait(false);
            });

            await app.RunAsync().ConfigureAwait(false);
            await timerTask.ConfigureAwait(false);
        }

        private static async Task ReadFromServerAndWriteToClient(NetworkStream server, WebSocket client, CancellationToken clientCancellationToken)
        {
            const int framing = 10;
            const int bufferSize = 4086;
            byte[] buffer = null;
            try
            {
                buffer = ArrayPool<byte>.Shared.Rent(bufferSize + framing);
                while (true)
                {
                    ushort bytesRead = (ushort)await server.ReadAsync(buffer.AsMemory(framing, bufferSize), clientCancellationToken).ConfigureAwait(false);
                    var packetHeader = new HTTP_PACKET_HEADER(HTTP_PACKET_TYPE.PKT_TYPE_DATA, framing + bytesRead);
                    MemoryMarshal.Write(buffer, in packetHeader);
                    MemoryMarshal.Write(buffer.AsSpan(8), in bytesRead);
                    await client.SendAsync(new ArraySegment<byte>(buffer, 0, framing + bytesRead), WebSocketMessageType.Binary, endOfMessage: true, clientCancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                if (buffer is not null)
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }

                server.Close();
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task HandShakeRequest(WebSocket ws, byte[] receiveBuffer, byte[] sendBuffer, Context context, CancellationToken cancellationToken)
        {
            if (context.RDPStateMachine != StateMachine.Initialized)
            {
                await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Invalid packet type", cancellationToken).ConfigureAwait(false);
                return;
            }

            var handShakeRequest = MemoryMarshal.AsRef<HTTP_HANDSHAKE_REQUEST_PACKET>(receiveBuffer.AsSpan(Marshal.SizeOf<HTTP_PACKET_HEADER>(), Marshal.SizeOf<HTTP_HANDSHAKE_REQUEST_PACKET>()));

            if (handShakeRequest.ExtendedAuth != 0x2) // HTTP_EXTENDED_AUTH_PAA - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/801ded3f-e14e-48f8-9b23-744914291edc
            {
                await ws.CloseAsync(WebSocketCloseStatus.PolicyViolation, "PAA Auth was not supplied by the client", cancellationToken).ConfigureAwait(false);
                return;
            }

            var handShakeResponse = new HTTP_HANDSHAKE_RESPONSE_PACKET
            {
                Hdr = new HTTP_PACKET_HEADER(HTTP_PACKET_TYPE.PKT_TYPE_HANDSHAKE_RESPONSE, Marshal.SizeOf<HTTP_HANDSHAKE_RESPONSE_PACKET>()),
                ErrorCode = 0,
                MajorVersion = 1,
                MinorVersion = 0,
                ServerVersion = 0,
                ExtendedAuth = 0x2, // HTTP_EXTENDED_AUTH_PAA - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/801ded3f-e14e-48f8-9b23-744914291edc
            };

            MemoryMarshal.Write(sendBuffer, in handShakeResponse);
            await ws.SendAsync(new ReadOnlyMemory<byte>(sendBuffer, 0, Marshal.SizeOf<HTTP_HANDSHAKE_RESPONSE_PACKET>()), WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);
            context.RDPStateMachine = StateMachine.HandShakeComplete;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task HandleTunnelCreate(WebSocket ws, byte[] receiveBuffer, byte[] sendBuffer, Context context, Func<string, (bool, HashSet<string>)> authorizeAndGetServerList, CancellationToken cancellationToken)
        {
            if (context.RDPStateMachine != StateMachine.HandShakeComplete)
            {
                await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Invalid packet type", cancellationToken).ConfigureAwait(false);
                return;
            }

            var tunnelPacket = MemoryMarshal.AsRef<HTTP_TUNNEL_PACKET>(receiveBuffer.AsSpan(Marshal.SizeOf<HTTP_PACKET_HEADER>(), Marshal.SizeOf<HTTP_TUNNEL_PACKET>()));

            var tunnelResponse = new HTTP_TUNNEL_RESPONSE
            {
                Hdr = new HTTP_PACKET_HEADER(HTTP_PACKET_TYPE.PKT_TYPE_TUNNEL_RESPONSE, Marshal.SizeOf<HTTP_TUNNEL_RESPONSE>()),
                ServerVersion = 0,
                StatusCode = 0,
                FieldsPresent = 0x3, // HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID | HTTP_TUNNEL_RESPONSE_FIELD_CAPS - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/8ea18228-f3f9-4849-9edb-2de1e950946b
                Reserved = 0,
                TunnelId = 0,
                Capabilities = 0x3F, // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/451c2bbf-10a2-4949-bfef-aef592d5c165
            };

            if ((tunnelPacket.FieldsPresent & 0x1) == 0) // HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/9db25d79-5e4a-4406-b72b-5429ef927b00
            {
                tunnelResponse.StatusCode = 0x800759D8;
            }
            else
            {
                var offset = Marshal.SizeOf<HTTP_PACKET_HEADER>() + Marshal.SizeOf<HTTP_TUNNEL_PACKET>();
                var cookieLength = BitConverter.ToUInt16(receiveBuffer, offset);
                var cookie = Encoding.Unicode.GetString(receiveBuffer, offset + sizeof(ushort), cookieLength - 2);

                (var authorized, context.AllowedServers) = authorizeAndGetServerList(cookie);
                if (!authorized)
                {
                    tunnelResponse.StatusCode = 0x800759F8; // E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED
                }
            }

            MemoryMarshal.Write(sendBuffer, in tunnelResponse);
            await ws.SendAsync(new ReadOnlyMemory<byte>(sendBuffer, 0, Marshal.SizeOf<HTTP_TUNNEL_RESPONSE>()), WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);

            if (tunnelResponse.StatusCode == 0)
            {
                context.RDPStateMachine = StateMachine.TunnelCreationComplete;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task HandleTunnleAuth(WebSocket ws, byte[] receiveBuffer, byte[] sendBuffer, Context context, CancellationToken cancellationToken)
        {
            if (context.RDPStateMachine != StateMachine.TunnelCreationComplete)
            {
                await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Invalid packet type", cancellationToken).ConfigureAwait(false);
                return;
            }

            var tunnelAuthRequest = MemoryMarshal.AsRef<HTTP_TUNNEL_AUTH_PACKET>(receiveBuffer.AsSpan(Marshal.SizeOf<HTTP_PACKET_HEADER>(), Marshal.SizeOf<HTTP_TUNNEL_AUTH_PACKET>()));
            var clientName = Encoding.Unicode.GetString(receiveBuffer, Marshal.SizeOf<HTTP_PACKET_HEADER>() + Marshal.SizeOf<HTTP_TUNNEL_AUTH_PACKET>(), tunnelAuthRequest.ClientNameLength - 2);
            Console.WriteLine($"{clientName} connecting.");

            var tunnelAuthResponse = new HTTP_TUNNEL_AUTH_RESPONSE
            {
                Hdr = new HTTP_PACKET_HEADER(HTTP_PACKET_TYPE.PKT_TYPE_TUNNEL_AUTH_RESPONSE, Marshal.SizeOf<HTTP_TUNNEL_AUTH_RESPONSE>()),
                ErrorCode = 0,
                FieldsPresent = 0x3, // HTTP_TUNNEL_AUTH_RESPONSE_FIELD_REDIR_FLAGS | HTTP_TUNNEL_AUTH_RESPONSE_FIELD_IDLE_TIMEOUT https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/d23570aa-5194-4b9f-9833-c8eefae71227
                Reserved = 0,
                RedirectFlags = 0x80000000, // HTTP_TUNNEL_REDIR_ENABLE_ALL - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/082ce217-d8fd-43ed-a564-bf161277695f
                IdleTimeout = 0
            };

            MemoryMarshal.Write(sendBuffer, in tunnelAuthResponse);
            await ws.SendAsync(new ReadOnlyMemory<byte>(sendBuffer, 0, Marshal.SizeOf<HTTP_TUNNEL_AUTH_RESPONSE>()), WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);
            context.RDPStateMachine = StateMachine.TunnelAuthorizationComplete;
        }

        private static async Task HandleChannelCreate(WebSocket ws, byte[] receiveBuffer, byte[] sendBuffer, Context context, CancellationToken cancellationToken)
        {
            if (context.RDPStateMachine != StateMachine.TunnelAuthorizationComplete)
            {
                await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Invalid packet type", cancellationToken).ConfigureAwait(false);
                return;
            }

            var channelCreateRequest = MemoryMarshal.AsRef<HTTP_CHANNEL_PACKET>(receiveBuffer.AsSpan(Marshal.SizeOf<HTTP_PACKET_HEADER>(), Marshal.SizeOf<HTTP_CHANNEL_PACKET>()));

            var serverName = Encoding.Unicode.GetString(receiveBuffer, Marshal.SizeOf<HTTP_PACKET_HEADER>() + Marshal.SizeOf<HTTP_CHANNEL_PACKET>(), channelCreateRequest.ServerNameLength - 2);

            uint errorCode = 0;

            if (!context.AllowedServers.Contains($"{serverName}:{channelCreateRequest.Port}", StringComparer.OrdinalIgnoreCase))
            {
                errorCode = 0x800759DA; // E_PROXY_CHANNEL_ACCESS_DENIED
            }
            else
            {
                var tcpClient = new TcpClient();
                context.Server = tcpClient;

                try
                {
                    using var timeout = new CancellationTokenSource(10 * 1000);
                    await tcpClient.ConnectAsync(serverName, channelCreateRequest.Port, timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    errorCode = 0x000059DD; // E_PROXY_TS_CONNECTFAILED
                }
                catch (SocketException)
                {
                    errorCode = 0x000059DD; // E_PROXY_TS_CONNECTFAILED
                }

                context.ServerStream = context.Server.GetStream();
            }

            var channelResponse = new HTTP_CHANNEL_RESPONSE
            {
                Hdr = new HTTP_PACKET_HEADER(HTTP_PACKET_TYPE.PKT_TYPE_CHANNEL_RESPONSE, Marshal.SizeOf<HTTP_CHANNEL_RESPONSE>()),
                FieldsPresent = 0x1, // HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/1ce779da-4948-4f3d-91e2-368584616fc0
                Reserved = 0,
                ChannelId = 0
            };

            MemoryMarshal.Write(sendBuffer, in channelResponse);
            await ws.SendAsync(new ReadOnlyMemory<byte>(sendBuffer, 0, Marshal.SizeOf<HTTP_CHANNEL_RESPONSE>()), WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);

            if (errorCode == 0)
            {
                context.RDPStateMachine = StateMachine.ChannelCreationComplete;
                context.ServerToClient = Task.Run(() => ReadFromServerAndWriteToClient(context.ServerStream, ws, cancellationToken), cancellationToken);
            }
        }

        private static async Task HandleKeepAlive(WebSocket ws, Context context, CancellationToken cancellationToken)
        {
            if (context.RDPStateMachine is not StateMachine.ChannelCreationComplete and not StateMachine.ChannelActive)
            {
                await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Invalid packet type", cancellationToken).ConfigureAwait(false);
                return;
            }
        }

        private static async Task HandleChannelClose(WebSocket ws, Context context, byte[] sendBuffer, CancellationToken cancellationToken)
        {
            if (context.RDPStateMachine != StateMachine.ChannelActive)
            {
                await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Invalid packet type", cancellationToken).ConfigureAwait(false);
            }

            var closeChannelResponse = new HTTP_CLOSE_CHANNEL_RESPONSE
            {
                Hdr = new HTTP_PACKET_HEADER(HTTP_PACKET_TYPE.PKT_TYPE_CLOSE_CHANNEL_RESPONSE, Marshal.SizeOf<HTTP_CLOSE_CHANNEL_RESPONSE>()),
                ErrorCode = 0,
                FieldsPresent = 0x1, // HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/1ce779da-4948-4f3d-91e2-368584616fc0
                Reserved = 0,
                ChannelId = 0
            };

            MemoryMarshal.Write(sendBuffer, in closeChannelResponse);
            await ws.SendAsync(new ReadOnlyMemory<byte>(sendBuffer, 0, Marshal.SizeOf<HTTP_CLOSE_CHANNEL_RESPONSE>()), WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);
        }

        private static async Task<string> GetIdTokenFromRefreshToken(string tokenUrl, string refreshToken, string clientId, string clientSecret)
        {
            using var httpClient = new HttpClient();
            using var requestBody = new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("refresh_token", refreshToken),
                new KeyValuePair<string, string>("grant_type", "refresh_token")
            ]);

            var response = await httpClient.PostAsync(new Uri(tokenUrl), requestBody).ConfigureAwait(false);
            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            string idToken = null;
            using var doc = JsonDocument.Parse(responseContent);
            foreach (var e in doc.RootElement.EnumerateObject())
            {
                if (e.NameEquals("id_token"))
                {
                    idToken = e.Value.GetString();
                }
            }

            return idToken;
        }

        private static async Task<(string refreshToken, string idToken)> ExchangeCodeForTokens(string tokenUrl, string clientId, string clientSecret, string redirectUrl, string code, CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, string>
            {
                { "client_id", clientId },
                { "client_secret", clientSecret },
                { "redirect_uri", redirectUrl },
                { "grant_type", "authorization_code" },
                { "code", System.Web.HttpUtility.UrlDecode(code) }
            };

            using var client = new HttpClient();
            using var content = new FormUrlEncodedContent(parameters);
            var clientResponse = await client.PostAsync(new Uri(tokenUrl), content, cancellationToken).ConfigureAwait(false);
            var responseContent = await clientResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            string refreshToken = null;
            string idToken = null;
            using var doc = JsonDocument.Parse(responseContent);
            foreach (var e in doc.RootElement.EnumerateObject())
            {
                if (e.NameEquals("refresh_token"))
                {
                    refreshToken = e.Value.GetString();
                }

                if (e.NameEquals("id_token"))
                {
                    idToken = e.Value.GetString();
                }
            }

            return (refreshToken, idToken);
        }

        private static async Task<(TimeSpan, Dictionary<string, string>)> GetGoogleOAuthPublicKeys(string publicKeyUrl)
        {
            using var client = new HttpClient();
            var response = await client.GetAsync(new Uri(publicKeyUrl)).ConfigureAwait(false);
            var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (response.Headers.CacheControl?.MaxAge is not TimeSpan maxAge)
            {
                maxAge = TimeSpan.FromHours(1);
            }

            using JsonDocument doc = JsonDocument.Parse(responseContent);
            var keys = new Dictionary<string, string>();
            foreach (var e in doc.RootElement.EnumerateObject())
            {
                keys.Add(e.Name, e.Value.GetString());
            }

            return (maxAge, keys);
        }

        private static bool VerifyRS256JWTSignature(string jwt, Dictionary<string, string> keys, out string payloadJson)
        {
            var jwtParts = jwt.Split('.');
            string headerJson = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(jwtParts[0]));

            string publicKey;
            using (var doc = JsonDocument.Parse(headerJson))
            {
                var kid = doc.RootElement.GetProperty("kid").GetString();
                if (!keys.TryGetValue(kid, out publicKey))
                {
                    throw new KeyNotFoundException("Public key not found for the given kid");
                }
            }

            payloadJson = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(jwtParts[1]));
            string dataToVerify = $"{jwtParts[0]}.{jwtParts[1]}";
            byte[] dataToVerifyBytes = Encoding.UTF8.GetBytes(dataToVerify);
            byte[] signatureBytes = WebEncoders.Base64UrlDecode(jwtParts[2]);

            using X509Certificate2 cert = X509Certificate2.CreateFromPem(publicKey);
            using RSA rsa = cert.PublicKey.GetRSAPublicKey();
            byte[] hash = SHA256.HashData(dataToVerifyBytes);

            return rsa.VerifyHash(hash, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        private static bool ValidateJWTAndExtractEmail(string payloadJson, string iss, string aud, out string email)
        {
            using JsonDocument doc = JsonDocument.Parse(payloadJson);
            var payload = doc.RootElement;

            email = null;
            if (DateTimeOffset.UtcNow > DateTimeOffset.FromUnixTimeSeconds((long)payload.GetProperty("exp").GetDouble()))
            {
                return false;
            }

            if (!string.Equals(payload.GetProperty("iss").GetString(), iss, StringComparison.Ordinal))
            {
                return false;
            }

            if (!string.Equals(payload.GetProperty("aud").GetString(), aud, StringComparison.Ordinal))
            {
                return false;
            }

            email = payload.GetProperty("email").GetString();
            return true;
        }

        private static (bool, HashSet<string>) AuthenticateAndGetServerList(string idToken, Dictionary<string, string> keys, Dictionary<string, HashSet<string>> allowUsers, GoogleOAuthConfig config)
        {
            try
            {
                if (!VerifyRS256JWTSignature(idToken, keys, out var payloadJson))
                {
                    return (false, null);
                }

                if (!ValidateJWTAndExtractEmail(payloadJson, GoogleOAuthConfig.Issuer, config.ClientId, out var email))
                {
                    return (false, null);
                }

                if (!allowUsers.TryGetValue(email, out var servers))
                {
                    return (false, null);
                }

                return (true, servers);
            }
            catch (FormatException)
            {
                return (false, null);
            }
        }

        private static byte[] AesDecrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            return aes.DecryptCbc(cipherText, iv);
        }

        private static (byte[] cipherText, byte[] iv) AesEncrypt(byte[] plainText, byte[] key)
        {
            using Aes aes = Aes.Create();
            aes.Key = key;
            return (aes.EncryptCbc(plainText, aes.IV), aes.IV);
        }

        private static byte[] GenerateAesKey()
        {
            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            return aes.Key;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task WebSocketLoopSlow(WebSocket ws, WebSocketMessageType messageType, Context context, byte[] receiveBuffer, byte[] sendBuffer, Func<string, (bool, HashSet<string>)> func, CancellationToken cancellationToken)
        {
            switch (messageType)
            {
                case WebSocketMessageType.Binary:
                    var header = MemoryMarshal.AsRef<HTTP_PACKET_HEADER>(receiveBuffer);
                    switch (header.PacketType)
                    {
                        case HTTP_PACKET_TYPE.PKT_TYPE_HANDSHAKE_REQUEST:
                            await HandShakeRequest(ws, receiveBuffer, sendBuffer, context, cancellationToken).ConfigureAwait(false);
                            break;
                        case HTTP_PACKET_TYPE.PKT_TYPE_TUNNEL_CREATE:
                            await HandleTunnelCreate(ws, receiveBuffer, sendBuffer, context, func, cancellationToken).ConfigureAwait(false);
                            break;
                        case HTTP_PACKET_TYPE.PKT_TYPE_TUNNEL_AUTH:
                            await HandleTunnleAuth(ws, receiveBuffer, sendBuffer, context, cancellationToken).ConfigureAwait(false);
                            break;
                        case HTTP_PACKET_TYPE.PKT_TYPE_CHANNEL_CREATE:
                            await HandleChannelCreate(ws, receiveBuffer, sendBuffer, context, cancellationToken).ConfigureAwait(false);
                            break;
                        case HTTP_PACKET_TYPE.PKT_TYPE_KEEPALIVE:
                            await HandleKeepAlive(ws, context, cancellationToken).ConfigureAwait(false);
                            break;
                        case HTTP_PACKET_TYPE.PKT_TYPE_CLOSE_CHANNEL:
                            await HandleChannelClose(ws, context, sendBuffer, cancellationToken).ConfigureAwait(false);
                            break;
                        default:
                            await ws.CloseAsync(WebSocketCloseStatus.InvalidPayloadData, "Invalid packet type", cancellationToken).ConfigureAwait(false);
                            break;
                    }
                    break;
                case WebSocketMessageType.Text:
                case WebSocketMessageType.Close:
                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, cancellationToken).ConfigureAwait(false);
                    break;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
        private static async Task WebSocketLoop(WebSocket ws, byte[] receiveBuffer, byte[] sendBuffer, Func<string, (bool, HashSet<string>)> func, CancellationToken cancellationToken)
        {
            Context context = new();
            while (!cancellationToken.IsCancellationRequested)
            {
                var messageType = (await ws.ReceiveAsync(new Memory<byte>(receiveBuffer), cancellationToken).ConfigureAwait(false)).MessageType; // TODO: what if I get < 8 bytes?
                if (messageType == WebSocketMessageType.Binary && receiveBuffer[0] == 0xA && context.RDPStateMachine > StateMachine.TunnelAuthorizationComplete)
                {
                    context.RDPStateMachine = StateMachine.ChannelActive;
                    await context.ServerStream.WriteAsync(receiveBuffer.AsMemory(10, (receiveBuffer[9] << 8) | receiveBuffer[8]), cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await WebSocketLoopSlow(ws, messageType, context, receiveBuffer, sendBuffer, func, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task HandleRemoteDesktopGateway(HttpContext context, Func<string, (bool, HashSet<string>)> func, CancellationToken cancellationToken)
        {
            var request = context.Request;

            if (string.Equals(request.Method, "RDG_OUT_DATA", StringComparison.OrdinalIgnoreCase))
            {
                request.Method = "GET";
            }

            var websockets = context.WebSockets;

            if (websockets.IsWebSocketRequest)
            {
                using var ws = await websockets.AcceptWebSocketAsync().ConfigureAwait(false);

                byte[] receiveBuffer = null;
                byte[] sendBuffer = null;

                try
                {
                    receiveBuffer = ArrayPool<byte>.Shared.Rent(4096);
                    sendBuffer = ArrayPool<byte>.Shared.Rent(4096);
                    await WebSocketLoop(ws, receiveBuffer, sendBuffer, func, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    if (receiveBuffer is not null)
                    {
                        ArrayPool<byte>.Shared.Return(receiveBuffer);
                    }

                    if (sendBuffer is not null)
                    {
                        ArrayPool<byte>.Shared.Return(sendBuffer);
                    }
                }
            }

            return;

        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task HandleIndex(HttpContext context, RDPGatewayConfig config, GoogleOAuthConfig authConfig, byte[] key, ECDsa ecdsa, CancellationToken cancellationToken)
        {
            var response = context.Response;

            if (!context.Request.Cookies.TryGetValue(config.CookieName, out var encryptedCookie))
            {
                response.Redirect(authConfig.LoginUrl);
                return;
            }

            if (!GetCookieInformation(encryptedCookie, key, ecdsa, config.AllowedUsers, out var email, out _, out var servers))
            {
                response.Redirect(authConfig.LoginUrl);
                return;
            }

            response.StatusCode = 200;
            response.ContentType = "text/html";

            await response.WriteAsync($"<!DOCTYPE html><html lang='en'><head><title>.</title></head><body><h1>{email}</h1><ul>", cancellationToken).ConfigureAwait(false);

            foreach (var server in servers)
            {
                await response.WriteAsync($"<li><a href='/genrdp?server={server}'>Download RDP File for {server}</li>", cancellationToken).ConfigureAwait(false);
            }

            await response.WriteAsync("</ul><a href='/logout'>Logout</a></body></html>", cancellationToken).ConfigureAwait(false);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task HandleGenRDP(HttpContext context, RDPGatewayConfig config, GoogleOAuthConfig authConfig, byte[] key, ECDsa ecdsa, CancellationToken cancellationToken)
        {
            var response = context.Response;

            var server = (string)context.Request.Query["server"];
            if (string.IsNullOrEmpty(server))
            {
                await response.WriteAsync($"server query parameter is missing.", cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!context.Request.Cookies.TryGetValue(config.CookieName, out var encryptedCookie))
            {
                response.Redirect(authConfig.LoginUrl);
                return;
            }

            if (!GetCookieInformation(encryptedCookie, key, ecdsa, config.AllowedUsers, out _, out var refreshToken, out var servers))
            {
                response.Redirect(authConfig.LoginUrl);
                return;
            }

            if (!servers.Contains(server))
            {
                await response.WriteAsync($"server is not in allow list.", cancellationToken).ConfigureAwait(false);
                return;
            }

            var idToken = await GetIdTokenFromRefreshToken(authConfig.TokenUrl, refreshToken, authConfig.ClientId, authConfig.ClientSecret).ConfigureAwait(false);
            string content = $"full address:s:{server}\r\ngatewaycredentialssource:i:5\r\ngatewayaccesstoken:s:{idToken}\r\ngatewayhostname:s:{config.ServerUrl}:{config.Port}\r\ngatewayprofileusagemethod:i:1\r\ngatewayusagemethod:i:1";
            context.Response.ContentType = "text/plain";
            context.Response.Headers.Append("Content-Disposition", $"attachment; filename={server}.rdp");
            await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(content), cancellationToken).ConfigureAwait(false);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task HandleLogin(HttpContext context, RDPGatewayConfig serverConfig, GoogleOAuthConfig authConfig, byte[] key, ECDsa signingKey, string x, string y, CancellationToken cancellationToken)
        {
            var response = context.Response;
            response.StatusCode = 200;
            response.ContentType = "text/html";

            var code = context.Request.Query["code"].ToString();
            if (string.IsNullOrEmpty(code))
            {
                await response.WriteAsync($"Code query parameter not found. <p><a href='{authConfig.LoginUrl}'>Login using your Google Account</a>.", cancellationToken).ConfigureAwait(false);
                return;
            }

            (var refreshToken, var idToken) = await ExchangeCodeForTokens(authConfig.TokenUrl, authConfig.ClientId, authConfig.ClientSecret, authConfig.RedirectUrl, code, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(idToken))
            {
                await response.WriteAsync("Failed to get refresh token or id token.", cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!VerifyRS256JWTSignature(idToken, authConfig.PublicKeys, out var payloadJson))
            {
                await response.WriteAsync("Failed to verify JWT id token.", cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!ValidateJWTAndExtractEmail(payloadJson, GoogleOAuthConfig.Issuer, authConfig.ClientId, out var email))
            {
                await response.WriteAsync("JWT validation failed.", cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!serverConfig.AllowedUsers.ContainsKey(email))
            {
                await response.WriteAsync($"User '{email}' is not in allow list.", cancellationToken).ConfigureAwait(false);
                return;
            }

            (var encryptedBytes, var iv) = AesEncrypt(Encoding.UTF8.GetBytes($"{email}:{refreshToken}"), key);

            var encryptedRefreshToken = CreateCookieValue(WebEncoders.Base64UrlEncode(iv), Guid.NewGuid().ToString("N"), WebEncoders.Base64UrlEncode(encryptedBytes), signingKey, x, y);
            var cookieOptions = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTimeOffset.Now.AddMonths(serverConfig.CookieExpiryMonths), IsEssential = true };
            response.Cookies.Append(serverConfig.CookieName, encryptedRefreshToken, cookieOptions);

            await response.WriteAsync("<!DOCTYPE html><html lang='en'><head><title>.</title><meta http-equiv='refresh' content='0; url=/'></head>Redirecting to /</body></html>", cancellationToken).ConfigureAwait(false);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task HandleLogout(HttpContext context, CancellationToken cancellationToken)
        {
            var response = context.Response;

            foreach (var cookie in context.Request.Cookies.Keys)
            {
                response.Cookies.Delete(cookie);
            }

            response.StatusCode = 200;
            response.ContentType = "text/html";
            await response.WriteAsync("<!DOCTYPE html><html lang='en'><head><title>.</title></head><body>All cookies cleared successfully.</body></html>", cancellationToken).ConfigureAwait(false);
        }

        private static string CreateCookieValue(string iv, string nonce, string base64UrlEncodedEncryptedBytes, ECDsa ecdsa, string x, string y)
        {
            var header = $$"""{"alg":"ES256","jwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"{{x}}","y":"{{y}}"},"nonce":"{{nonce}}","iv":"{{iv}}"}""";
            var payload = $$"""{"eb":"{{base64UrlEncodedEncryptedBytes}}"}""";
            return FlattenedJWSJSONSerialization(header, payload, ecdsa);
        }

        private static string FlattenedJWSJSONSerialization(string header, string payload, ECDsa ecdsa)
        {
            string base64UrlEncodedHeader = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header));
            string base64UrlEncodedPayload = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
            string base64UrlEncodedSignature = WebEncoders.Base64UrlEncode(ecdsa.SignData(Encoding.UTF8.GetBytes($"{base64UrlEncodedHeader}.{base64UrlEncodedPayload}"), HashAlgorithmName.SHA256));
            return $$"""{"protected":"{{base64UrlEncodedHeader}}","payload":"{{base64UrlEncodedPayload}}","signature":"{{base64UrlEncodedSignature}}"}""";
        }

        private static bool VerifyJWSAndExtractInformation(string json, ECDsa ecdsa, out byte[] iv, out byte[] eb)
        {
            bool retVal;
            string protectedHeader;
            string payload;

            iv = null;
            eb = null;

            try
            {
                using (var doc = JsonDocument.Parse(json))
                {
                    JsonElement root = doc.RootElement;
                    string base64UrlEncodedHeader = root.GetProperty("protected").GetString();
                    protectedHeader = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(base64UrlEncodedHeader));
                    string base64UrlEncodedPayload = root.GetProperty("payload").GetString();
                    payload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(base64UrlEncodedPayload));
                    var sb = WebEncoders.Base64UrlDecode(root.GetProperty("signature").GetString());
                    retVal = ecdsa.VerifyData(Encoding.UTF8.GetBytes($"{base64UrlEncodedHeader}.{base64UrlEncodedPayload}"), sb, HashAlgorithmName.SHA256);
                }

                using (var doc = JsonDocument.Parse(protectedHeader))
                {
                    JsonElement root = doc.RootElement;
                    iv = WebEncoders.Base64UrlDecode(root.GetProperty("iv").GetString());
                }

                using (var doc = JsonDocument.Parse(payload))
                {
                    JsonElement root = doc.RootElement;
                    eb = WebEncoders.Base64UrlDecode(root.GetProperty("eb").GetString());
                }
            }
            catch (JsonException)
            {
                retVal = false;
            }
            

            return retVal;
        }

        private static bool GetCookieInformation(string encryptedCookieJWS, byte[] key, ECDsa ecdsa, Dictionary<string, HashSet<string>> allowedUsers, out string email, out string refreshToken, out HashSet<string> servers)
        {
            email = null;
            refreshToken = null;
            servers = null;

            if (!VerifyJWSAndExtractInformation(encryptedCookieJWS, ecdsa, out var iv, out var eb))
            {
                return false;
            }

            string[] cookieValues;
            try
            {
                cookieValues = Encoding.UTF8.GetString(AesDecrypt(eb, key, iv)).Split(':');
            }
            catch (CryptographicException)
            {
                return false;
            }

            email = cookieValues[0];
            if (!allowedUsers.TryGetValue(email, out servers))
            {
                return false;
            }

            refreshToken = cookieValues[1];

            return true;
        }
    }

    internal sealed class RDPGatewayConfig
    {
        public string ServerUrl { get; set; }

        public int Port { get; set; }

        public string PathToTLSCertificatePEM { get; set; }

        public string CookieName { get; set; }

        public int CookieExpiryMonths { get; set; }

        public string PathToGoogleOAuthClientSecretFile { get; set; }

        public Dictionary<string, HashSet<string>> AllowedUsers { get; set; }

        public static RDPGatewayConfig Parse(string json)
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            var config = new RDPGatewayConfig
            {
                ServerUrl = root.GetProperty(nameof(ServerUrl)).GetString(),
                Port = root.GetProperty(nameof(Port)).GetInt32(),
                PathToTLSCertificatePEM = root.GetProperty(nameof(PathToTLSCertificatePEM)).GetString(),
                CookieName = root.GetProperty(nameof(CookieName)).GetString(),
                CookieExpiryMonths = root.GetProperty(nameof(CookieExpiryMonths)).GetInt32(),
                PathToGoogleOAuthClientSecretFile = root.GetProperty(nameof(PathToGoogleOAuthClientSecretFile)).GetString(),
                AllowedUsers = []
            };

            JsonElement allowedUsers = root.GetProperty(nameof(AllowedUsers));
            foreach (var user in allowedUsers.EnumerateArray())
            {
                var email = user.GetProperty("Email").GetString();
                var servers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var server in user.GetProperty("Servers").EnumerateArray())
                {
                    servers.Add(server.GetString());
                }

                config.AllowedUsers.Add(email, servers);
            }

            return config;
        }
    }

    internal sealed class GoogleOAuthConfig
    {
        public static string Issuer => "https://accounts.google.com";

        public string TokenUrl { get; private set; }

        public string ClientId { get; private set; }

        public string ClientSecret { get; private set; }

        public string RedirectUrl { get; private set; }

        public string LoginUrl { get; private set; }

        public string PublicKeysUrl { get; private set; }

        public Dictionary<string, string> PublicKeys { get; set; }

        public static GoogleOAuthConfig Parse(string json)
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;
            JsonElement web = root.GetProperty("web");

            string redirectUrl = null;
            foreach (var e in web.GetProperty("redirect_uris").EnumerateArray())
            {
                redirectUrl = e.GetString();
                break;
            }

            if (string.IsNullOrEmpty(redirectUrl))
            {
                throw new NotSupportedException("No redirect URI found in the Google OAuth configuration");
            }

            string clientId = web.GetProperty("client_id").GetString();

            return new GoogleOAuthConfig
            {
                ClientId = clientId,
                ClientSecret = web.GetProperty("client_secret").GetString(),
                PublicKeysUrl = web.GetProperty("auth_provider_x509_cert_url").GetString(),
                RedirectUrl = redirectUrl,
                TokenUrl = web.GetProperty("token_uri").GetString(),
                LoginUrl = $"{web.GetProperty("auth_uri").GetString()}?client_id={clientId}&redirect_uri={redirectUrl}&response_type=code&access_type=offline&prompt=consent&scope=openid email"
            };
        }
    }

    internal sealed class Context
    {
        public StateMachine RDPStateMachine { get; set; }

        public TcpClient Server { get; set; }

        public NetworkStream ServerStream { get; set; }

        public Task ServerToClient { get; set; }

        public HashSet<string> AllowedServers { get; set; }
    }

    internal enum StateMachine
    {
        Initialized,
        HandShakeComplete,
        TunnelCreationComplete,
        TunnelAuthorizationComplete,
        ChannelCreationComplete,
        ChannelActive
    }

    internal enum HTTP_PACKET_TYPE : ushort
    {
        UNUSED = 0x0,
        PKT_TYPE_HANDSHAKE_REQUEST = 0x1,
        PKT_TYPE_HANDSHAKE_RESPONSE = 0x2,
        PKT_TYPE_EXTENDED_AUTH_MSG = 0x3,
        PKT_TYPE_TUNNEL_CREATE = 0x4,
        PKT_TYPE_TUNNEL_RESPONSE = 0x5,
        PKT_TYPE_TUNNEL_AUTH = 0x6,
        PKT_TYPE_TUNNEL_AUTH_RESPONSE = 0x7,
        PKT_TYPE_CHANNEL_CREATE = 0x8,
        PKT_TYPE_CHANNEL_RESPONSE = 0x9,
        PKT_TYPE_DATA = 0xA,
        PKT_TYPE_SERVICE_MESSAGE = 0xB,
        PKT_TYPE_REAUTH_MESSAGE = 0xC,
        PKT_TYPE_KEEPALIVE = 0xD,
        PKT_TYPE_CLOSE_CHANNEL = 0x10,
        PKT_TYPE_CLOSE_CHANNEL_RESPONSE = 0x11
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_PACKET_HEADER(HTTP_PACKET_TYPE packetType, int packetLength)
    {
        [FieldOffset(0)]
        public HTTP_PACKET_TYPE PacketType = packetType;

        [FieldOffset(2)]
        public ushort Reserved = 0;

        [FieldOffset(4)]
        public uint PacketLength = (uint)packetLength;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_HANDSHAKE_REQUEST_PACKET
    {
        [FieldOffset(0)]
        public byte MajorVersion;

        [FieldOffset(1)]
        public byte MinorVersion;

        [FieldOffset(2)]
        public ushort ClientVersion;

        [FieldOffset(4)]
        public ushort ExtendedAuth;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_TUNNEL_AUTH_PACKET
    {
        [FieldOffset(0)]
        public ushort FieldsPresent;

        [FieldOffset(2)]
        public ushort ClientNameLength;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_TUNNEL_AUTH_RESPONSE
    {
        [FieldOffset(0)]
        public HTTP_PACKET_HEADER Hdr;

        [FieldOffset(8)]
        public uint ErrorCode;

        [FieldOffset(12)]
        public ushort FieldsPresent;

        [FieldOffset(14)]
        public ushort Reserved;

        [FieldOffset(16)]
        public uint RedirectFlags;

        [FieldOffset(20)]
        public uint IdleTimeout;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_TUNNEL_PACKET
    {
        [FieldOffset(0)]
        public uint CapsFlags;

        [FieldOffset(4)]
        public ushort FieldsPresent;

        [FieldOffset(6)]
        public ushort Reserved;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    internal struct HTTP_TUNNEL_RESPONSE
    {
        [FieldOffset(0)]
        public HTTP_PACKET_HEADER Hdr;

        [FieldOffset(8)]
        public ushort ServerVersion;

        [FieldOffset(10)]
        public uint StatusCode;

        [FieldOffset(14)]
        public ushort FieldsPresent;

        [FieldOffset(16)]
        public ushort Reserved;

        [FieldOffset(18)]
        public uint TunnelId;

        [FieldOffset(22)]
        public uint Capabilities;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_HANDSHAKE_RESPONSE_PACKET
    {
        [FieldOffset(0)]
        public HTTP_PACKET_HEADER Hdr;

        [FieldOffset(8)]
        public uint ErrorCode;

        [FieldOffset(12)]
        public byte MajorVersion;

        [FieldOffset(13)]
        public byte MinorVersion;

        [FieldOffset(14)]
        public ushort ServerVersion;

        [FieldOffset(16)]
        public ushort ExtendedAuth;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_CHANNEL_PACKET
    {
        [FieldOffset(0)]
        public byte NumResources;

        [FieldOffset(1)]
        public byte NumAltResources;

        [FieldOffset(2)]
        public ushort Port;

        [FieldOffset(4)]
        public ushort Protocol;

        [FieldOffset(6)]
        public ushort ServerNameLength;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_CHANNEL_RESPONSE
    {
        [FieldOffset(0)]
        public HTTP_PACKET_HEADER Hdr;

        [FieldOffset(8)]
        public uint ErrorCode;

        [FieldOffset(12)]
        public ushort FieldsPresent;

        [FieldOffset(14)]
        public ushort Reserved;

        [FieldOffset(16)]
        public uint ChannelId;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct HTTP_CLOSE_CHANNEL_RESPONSE
    {
        [FieldOffset(0)]
        public HTTP_PACKET_HEADER Hdr;

        [FieldOffset(8)]
        public uint ErrorCode;

        [FieldOffset(12)]
        public ushort FieldsPresent;

        [FieldOffset(14)]
        public ushort Reserved;

        [FieldOffset(16)]
        public uint ChannelId;
    }
}