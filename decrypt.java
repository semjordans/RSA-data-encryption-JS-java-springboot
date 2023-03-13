import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@RestController
public class MyController {

  @PostMapping("/api/data")
  public String postData(@RequestBody RequestBody requestBody) throws NoSuchAlgorithmException, InvalidKeyException {
    // Get the data and hash from the request body
    String jsonString = requestBody.getData().toString();
    String hash = requestBody.getHash();

    // Create a SecretKeySpec with the secret key
    String secretKey = "MySecretKey";
    SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");

    // Compute the hash of the data using the secret key
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(keySpec);
    byte[] dataHash = mac.doFinal(jsonString.getBytes(StandardCharsets.UTF_8));
    String computedHash = Base64.getEncoder().encodeToString(dataHash);

    // Compare the computed hash with the hash from the request
    if (!computedHash.equals(hash)) {
      // The data has been tampered with
      return "Error: Invalid hash";
    }

    // The data is valid, so decrypt it
    // First, deserialize the JSON string into a Java object
    ObjectMapper objectMapper = new ObjectMapper();
    Data data = objectMapper.readValue(jsonString, Data.class);

    // Next, use the salt to compute the password hash
    String salt = data.getSalt();
    String password = data.getPassword();
    byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
    byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec keySpec = new PBEKeySpec(passwordBytes, saltBytes, 1000, 64 * 8);
    byte[] hashedPassword = keyFactory.generateSecret(keySpec).getEncoded();
    String hashedPasswordString = Base64.getEncoder().encodeToString(hashedPassword);

    // Finally, set the decrypted data in a Java object and return it
    data.setPassword(hashedPasswordString);
    return data.toString();
  }
}
