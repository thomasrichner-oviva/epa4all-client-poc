package com.oviva.telematik.epaapi;

import static org.junit.jupiter.api.Assertions.*;

import com.oviva.epa.client.konn.internal.util.NaiveTrustManager;
import com.oviva.telematik.vau.epa4all.client.authz.AuthorizationService;
import com.oviva.telematik.vau.epa4all.client.info.InformationService;
import com.oviva.telematik.vau.epa4all.client.internal.RsaSignatureAdapter;
import com.oviva.telematik.vau.httpclient.internal.DowngradeHttpClient;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.proxy.Main;
import de.gematik.epa.conversion.internal.enumerated.*;
import de.gematik.epa.ihe.model.Author;
import de.gematik.epa.ihe.model.document.Document;
import de.gematik.epa.ihe.model.document.DocumentMetadata;
import de.gematik.epa.ihe.model.simple.AuthorInstitution;
import java.net.*;
import java.net.http.HttpClient;
import java.security.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EndToEndTest {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String KONNEKTOR_PROXY_HOST = "127.0.0.1";
  private static final int KONNEKTOR_PROXY_PORT = 3128;

  private enum Enabler {
    EPA_DEPLOYMENT,
    RISE;
  }

  private final Enabler enabler = Enabler.RISE;
  private Main app;

  @BeforeEach
  void setUp() {
    var proxy = new InetSocketAddress(KONNEKTOR_PROXY_HOST, KONNEKTOR_PROXY_PORT);
    if (enabler == Enabler.EPA_DEPLOYMENT) {
      proxy = null;
    }
    app = new Main(new Main.Configuration(proxy));

    // VAU base URI is dynamic!
    app.start();
  }

  @AfterEach
  void tearDown() {
    app.stop();
  }

  @Test
  void e2e() throws Exception {

    // ----
    // Prerequisites:
    // - build diga-epa-lib from: https://github.com/oviva-ag/diga-epa-lib/tree/feature/epa-3-0
    // - install https://github.com/gematik/lib-ihe-xds/tree/2.0.2 locally

    var konnektorService = TestKonnektors.riseKonnektor_RU();

    // client -> jumphost proxy -> (Internet || ( RISE VPN -> Telematikinfra) )
    var outerHttpClient = buildOuterHttpClient();

    // ----
    // 1. find the enabler hosting the ePA for the given insurant (Krankenversicherten Nummber -
    // KVNR)

    //    var insurantId = "Z987654321";
    //        var insurantId = "X110467329"; // RISE
    //    final var insurantId = "X110580673"; // fBeta
    final var insurantId = "X229678976"; // fBeta
    // X229678976 // RISE with access from Oviva's SMB-C

    // Oviva
    // those are not authorized in the FdV
    // KVNR: X110467329
    // KVNR: X110485695
    // KVNR: X110406713

    var providers =
        List.of(InformationService.EpaProvider.IBM, InformationService.EpaProvider.BITMARCK);
    var informationService =
        new InformationService(outerHttpClient, InformationService.Environment.DEV, providers);

    var endpoint =
        informationService
            .findAccountEndpoint(insurantId)
            .orElseGet(
                () -> {
                  fail("KVNR %s doesnt exist".formatted(insurantId));
                  return null;
                });

    // ----
    // 2. set-up client to proxy through the VAU tunnel

    // client -> proxy-server (vau-tunnel wrapper, forward proxy) -> jumphost proxy -> RISE VPN
    // (wireguard) -> Telematikinfra

    var vauProxyServerAddr = new InetSocketAddress("127.0.0.1", 7777);

    // HTTP client used to communicate inside the VAU tunnel
    var innerHttpClient =
        HttpClient.newBuilder()
            // this is the local VAU termination proxy
            .proxy(ProxySelector.of(vauProxyServerAddr))
            // no redirects, wee need to deal with redirects from authorization directly
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(7))
            // within the VAU tunnel HTTP/1.1 is preferred
            .version(HttpClient.Version.HTTP_1_1)
            .build();

    // we need to downgrade HTTPS requests to HTTP, otherwise the proxy can't deal with the requests
    var innerVauClient = new DowngradeHttpClient(JavaHttpClient.from(innerHttpClient));

    var signer = new RsaSignatureAdapter(konnektorService);
    var authorizationService =
        new AuthorizationService(innerVauClient, outerHttpClient, endpoint, signer);

    // ----
    // 3. authenticate the client-side of the VAU tunnel
    assertDoesNotThrow(() -> authorizationService.authorizeVauWithSmcB(insurantId));

    // => tunnel is now authorized, let the fun begin

    // ----
    // 4. interact with the document management service

    // we need to downgrade the URI we got, this goes through the VAU tunnel
    var phrEndpoint = downgradeUri(endpoint).resolve("/epa/xds-document/api/I_Document_Management");

    // setup the soap client to go via VAU proxy
    var client =
        new SoapClientFactory(new ClientConfiguration(new InetSocketAddress("localhost", 7777)));
    var phrManagementPort = client.getIDocumentManagementPort(phrEndpoint);
    var phrService = new PhrService(phrManagementPort);

    // Oviva Testkarte SMC-B
    // TODO: read from SMC-B
    var institutionName = "DiGA-Hersteller und Anbieter Prof. Dr. Tina Gräfin CesaTEST-ONLY";
    var telematikId = "9-SMC-B-Testkarte-883110000145356";
    var authorInstitution = new AuthorInstitution(institutionName, telematikId);

    // NOTE: as of now only FHIR seems to work, specifically PDF/A don't work
    var id = UUID.randomUUID();
    var mediaType = "application/fhir+xml";
    var body = ExportFixture.fhirDocumentWithId(id); // the bundle ID must be different

    var document = buildDocumentPayload(id, insurantId, authorInstitution, mediaType, body);

    assertDoesNotThrow(() -> phrService.writeDocument(insurantId, document));

    System.out.println("Success!");
  }

  private URI downgradeUri(URI u) {

    var port = u.getPort();
    var scheme = u.getScheme();
    if ("http".equals(scheme)) {
      return u;
    }

    if (((port == 443) || (port == -1)) && "https".equals(scheme)) {
      return URI.create("http://%s%s".formatted(u.getHost(), u.getPath()));
    }

    throw new IllegalArgumentException("failed downgrading uri=%s".formatted(u));
  }

  private HttpClient buildOuterHttpClient() {

    if (enabler == Enabler.EPA_DEPLOYMENT) {
      return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    }

    SSLContext sslContext = null;
    try {
      sslContext = SSLContext.getInstance("TLSv1.3");
      sslContext.init(null, new TrustManager[] {new NaiveTrustManager()}, null);
    } catch (KeyManagementException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    return HttpClient.newBuilder()
        // TODO: use proper truststore
        .sslContext(sslContext)
        // Returned URLs actually need to be resolved via the
        // proxy, their FQDN is only resolved within the TI
        .proxy(ProxySelector.of(new InetSocketAddress(KONNEKTOR_PROXY_HOST, KONNEKTOR_PROXY_PORT)))
        .connectTimeout(Duration.ofSeconds(10))
        .build();
  }

  private Document buildDocumentPayload(
      UUID id, String kvnr, AuthorInstitution authorInstitution, String mimeType, byte[] contents) {

    // IMPORTANT: Without the urn prefix we can't replace it later
    var documentUuid = "urn:uuid:" + id;

    return new Document(
        contents,
        new DocumentMetadata(
            List.of(
                // Telematik-ID der DiGA^Name der DiGA (Name der
                // Verordnungseinheit)^Oviva-AG^^^^^^&<OID für DiGAs, wie in professionOID>&ISO
                // https://gemspec.gematik.de/docs/gemSpec/gemSpec_DM_ePA_EU-Pilot/gemSpec_DM_ePA_EU-Pilot_V1.53.1/#2.1.4.3.1
                new Author(
                    authorInstitution.identifier(),
                    "Oviva Direkt für Adipositas",
                    "Oviva AG",
                    "",
                    "",
                    "",
                    // professionOID for DiGA:
                    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/gemSpec_OID_V3.19.0/#3.5.1.3
                    // TODO read this from the SMC-B, see
                    // com.oviva.epa.client.internal.svc.utils.CertificateUtils::getProfessionInfoFromCertificate
                    "1.2.276.0.76.4.282", // OID
                    // Der identifier in AuthorInstitution muss eine gültige TelematikId sein, so
                    // wie sie z. B. auf der SMC-B-Karte enthalten ist
                    List.of(authorInstitution),
                    List.of("12^^^&amp;1.3.6.1.4.1.19376.3.276.1.5.13&amp;ISO"),
                    List.of("25^^^&1.3.6.1.4.1.19376.3.276.1.5.11&ISO"),
                    List.of("^^Internet^telematik-infrastructure@oviva.com"))),
            "AVAILABLE",
            List.of(ConfidentialityCode.NORMAL.getValue()),
            ClassCode.DURCHFUEHRUNGSPROTOKOLL.getValue(),
            "DiGA MIO-Beispiel eines Dokument von Referenzimplementierung geschickt (Simple Roundtrip)",
            LocalDateTime.now().minusHours(3),
            documentUuid,
            List.of(
                EventCode.VIRTUAL_ENCOUNTER.getValue(), EventCode.PATIENTEN_MITGEBRACHT.getValue()),
            FormatCode.DIGA.getValue(),
            "",
            HealthcareFacilityCode.PATIENT_AUSSERHALB_BETREUUNG.getValue(),
            "de-DE",
            "",
            mimeType,
            PracticeSettingCode.PATIENT_AUSSERHALB_BETREUUNG.getValue(),
            List.of(),
            null,
            null,
            contents.length,
            "Protokoll %s.xml".formatted(id),
            TypeCode.PATIENTENEIGENE_DOKUMENTE.getValue(),
            documentUuid,
            "Oviva_DiGA_Export_%s".formatted(id),
            "",
            "",
            kvnr),
        null);
  }
}
