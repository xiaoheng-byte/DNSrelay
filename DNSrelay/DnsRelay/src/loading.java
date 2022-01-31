import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Scanner;

public class loading {
	public static final int LOCAL_PORT = 53;

	public static void main(String[] args) throws UnknownHostException {
		System.out.println("------------------------------------");
		System.out.println("Please Enter DNS Server IP : ");
		Scanner sc = new Scanner(System.in);
		String DNS_IP = sc.nextLine();
		sc.close();
		System.out.println("Server : " + DNS_IP);
		System.out.println("Bind UDP port : " + LOCAL_PORT);
		System.out.println("Try to load table : \"dnsrelay.txt\" ");
		Check check = new Check();
		try {
			check.readData("dnsrelay.txt");
			System.out.println("There are " + check.ipTable.size() + " names in table");
			System.out.println("------------------------------------");
			DNSRelay rel = new DNSRelay();
			rel.init(check, DNS_IP);
		} catch (IOException e) {
			System.out.println("Failed to load table!");
			System.out.println("------------------------------------");
			e.printStackTrace();
		}
	}
}
