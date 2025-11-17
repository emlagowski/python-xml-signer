import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.apache.xml.security.Init
import org.apache.xml.security.signature.XMLSignature
import org.apache.xml.security.transforms.Transforms
import org.apache.xml.security.utils.Constants
import org.w3c.dom.Document
import java.io.ByteArrayInputStream
import java.io.StringWriter
import java.security.KeyStore
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

fun main() {
    Init.init()
    
    val keystorePath = System.getenv("KEYSTORE_PATH") ?: "/app/keystore.jks"
    val keystorePassword = System.getenv("KEYSTORE_PASSWORD") ?: "changeit"
    val port = System.getenv("PORT")?.toIntOrNull() ?: 8080
    
    println("🔐 Loading keystore from: $keystorePath")
    val keyStore = KeyStore.getInstance("JKS")
    keyStore.load(java.io.FileInputStream(keystorePath), keystorePassword.toCharArray())
    val alias = keyStore.aliases().nextElement()
    val privateKey = keyStore.getKey(alias, keystorePassword.toCharArray()) as java.security.PrivateKey
    val cert = keyStore.getCertificate(alias)
    println("✅ Keystore loaded successfully (alias: $alias)")
    
    embeddedServer(Netty, port = port) {
        routing {
            get("/health") {
                call.respondText("OK")
            }
            
            post("/sign") {
                try {
                    val xmlContent = call.receiveText()
                    println("📝 Received XML for signing (${xmlContent.length} bytes)")
                    val doc = parseXml(xmlContent)
                    val signedXml = signXml(doc, privateKey, cert.publicKey)
                    println("✅ XML signed successfully")
                    call.respondText(signedXml, io.ktor.http.ContentType.Application.Xml)
                } catch (e: Exception) {
                    println("❌ Error signing XML: ${e.message}")
                    e.printStackTrace()
                    call.respondText("Error: ${e.message}", status = io.ktor.http.HttpStatusCode.BadRequest)
                }
            }
        }
    }.apply {
        println("🚀 Server starting on http://0.0.0.0:$port")
    }.start(wait = true)
}

fun parseXml(xml: String): Document {
    val dbFactory = DocumentBuilderFactory.newInstance()
    dbFactory.isNamespaceAware = true
    val dBuilder = dbFactory.newDocumentBuilder()
    return dBuilder.parse(ByteArrayInputStream(xml.toByteArray()))
}

fun signXml(doc: Document, privateKey: java.security.PrivateKey, publicKey: java.security.PublicKey): String {
    val sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256
    val sig = XMLSignature(doc, "", sigAlgo, Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
    
    val envelope = doc.documentElement
    val soapNs = envelope.namespaceURI
    
    val header = envelope.getElementsByTagNameNS(soapNs, "Header").item(0)
        ?: doc.createElementNS(soapNs, "soapenv:Header").also {
            envelope.insertBefore(it, envelope.firstChild)
        }
    
    val securityNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    val security = doc.createElementNS(securityNs, "wsse:Security")
    security.setAttributeNS("http://schemas.xmlsoap.org/soap/envelope/", "soapenv:mustUnderstand", "1")
    header.appendChild(security)
    security.appendChild(sig.element)
    
    val transforms = Transforms(doc)
    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE)
    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS)
    sig.addDocument("", transforms, "http://www.w3.org/2001/04/xmlenc#sha256")
    
    sig.addKeyInfo(publicKey)
    sig.sign(privateKey)
    
    return documentToString(doc)
}

fun documentToString(doc: Document): String {
    val transformer = TransformerFactory.newInstance().newTransformer()
    val writer = StringWriter()
    transformer.transform(DOMSource(doc), StreamResult(writer))
    return writer.toString()
}