import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class DNSRelay {
	public String DNS_IP;
	public static final int DNS_PORT = 53;
	private static final int DATA_LEN = 4096; // data_len代表包的最大容量

	byte[] inBuff = new byte[DATA_LEN];
	Check check;
	DatagramSocket socket;
	private DatagramPacket inPacket = new DatagramPacket(inBuff, inBuff.length); // 接受包
	private DatagramPacket outPacket; // 转发包
	private byte[] sendData;
	byte[] finalData;
	private String domainNameStr; // 解析域名
	private InetAddress resolverAddress; // resolver ip 地址和端口
	private int resolverPort;
	private boolean IPv6_Flag = false; // 包类型为 ipv6 标志
	int udpCursor;
	int ansCursor;
	private Map<Integer, IDTransition> idMap = new HashMap<Integer, IDTransition>();

	public void init(Check check, String DNS_IP) {
		this.check = check;
		this.DNS_IP = DNS_IP;
		try {
			socket = new DatagramSocket(DNS_PORT);
			listener();
		} catch (Exception e) {
			socket.close();
			e.printStackTrace();
		}
	}

	public String getDomainName() {
		String domainName = "";
		udpCursor = 12;
		int length = byteToInt(sendData, udpCursor);
		while (length != 0) {
			udpCursor++;
			domainName += byteToString(sendData, udpCursor, length) + ".";
			udpCursor += length;
			length = byteToInt(sendData, udpCursor);
		}
		udpCursor++;

		// 判断数据包类型是否为 IPv6 类型。 若是将 IPv6_Flag 设置为 True
		if (sendData[udpCursor] == 0x00 && sendData[udpCursor + 1] == 0x1c)
			IPv6_Flag = true;
		udpCursor += 4;

		// 返回域名并去除末尾的'.'
		return domainName.substring(0, domainName.length() - 1);
	}

	public void listener() throws IOException {
		while (true) {
			socket.receive(inPacket); // 接收 UDP 报文
			sendData = inPacket.getData(); // 获得 DNS 数据

			if (isQuery())
				handleQuery(); // query
			else
				handleResponse(); // response
		}
	}

	public void handleQuery() throws IOException {
		Date receiveTime = new Date();
		domainNameStr = getDomainName(); // 获得域名
		System.out.println("\n接受时间：" + receiveTime);
		System.out.println("域名: " + domainNameStr);
		resolverAddress = inPacket.getAddress(); // 存储报的来源地址和端口号
		resolverPort = inPacket.getPort();
		if (check.ipTable.containsKey(domainNameStr))
			localDNS(); // 本地域名解析表中找到
		else
			remoteDNS();

	}

	public void handleResponse() throws IOException {
		int responseID = byteToShort(sendData);
		if (idMap.containsKey(responseID)) {
			IDTransition id = idMap.get(responseID);
			outPacket = new DatagramPacket(sendData, sendData.length, id.getAddr(), id.getPort()); // 转发收到的远端 DNS 的 //
																									// response
			socket.send(outPacket);
		}
	}

	public boolean isQuery() {
		return ((sendData[2] & 0x80) == 0x00);
	}

	public void localDNS() throws IOException {
		String LocalDNSipAddress = check.ipTable.get(domainNameStr);

		if (LocalDNSipAddress.equals("0.0.0.0"))
			shield();// 如果 IP 为 0.0.0.0
		else
			relay(); // 如果不为 0.0.0.0 本地组装 UDP 报文并发回 resolver 响应
	}

	public void shield() throws IOException {
		System.out.println("结果：" + "屏蔽"); // 屏蔽
		sendData[2] = (byte) (sendData[2] | 0x81); // 修改标志位 response (flag=0x8183) rcode=3
		sendData[3] = (byte) (sendData[3] | 0x83);
		outPacket = new DatagramPacket(sendData, sendData.length, resolverAddress, resolverPort); // 包装数据并发送
		socket.send(outPacket);
		IPv6_Flag = false;
	}

	public void relay() throws IOException {
		if (IPv6_Flag)
			remoteDNS();// 返回IPv4 组包
		else {
			finalData = new byte[udpCursor + 16];
			ansCursor = 0; // 回答cursor
			setAnswerCount();
			setName();
			setType();
			setClass();
			setTTL();
			setIPLength();
			setResponseIP();
			outPacket = new DatagramPacket(finalData, finalData.length, resolverAddress, resolverPort);
			socket.send(outPacket);
		} // 响应请求，发送 UDP 报文
	}

	public void setAnswerCount() {
		System.out.println("功能：" + "IPV4 本地响应");
		// 修改标志位 response (flag=0x8180)
		// 设置 Answer count 为 1
		sendData[2] = (byte) (sendData[2] | 0x81);
		sendData[3] = (byte) (sendData[3] | 0x80);
		sendData[6] = (byte) (sendData[6] | 0x00);
		sendData[7] = (byte) (sendData[7] | 0x01);
		System.arraycopy(sendData, 0, finalData, ansCursor, udpCursor);
	}

	// 保存 name
	public void setName() {
		ansCursor = udpCursor;
		short name = (short) 0xc00c;
		System.arraycopy(shortToByte(name), 0, finalData, ansCursor, 2);
		ansCursor += 2;
	}

	// 保存 typeA
	public void setType() {
		short typeA = (short) 0x0001;
		System.arraycopy(shortToByte(typeA), 0, finalData, ansCursor, 2);
		ansCursor += 2;
	}

	// 保存 classA
	public void setClass() {
		short classA = (short) 0x0001;
		System.arraycopy(shortToByte(classA), 0, finalData, ansCursor, 2);
		ansCursor += 2;
	}

	// 保存 timeLive
	public void setTTL() {
		int timeLive = 0x00015180;
		System.arraycopy(intToByte(timeLive), 0, finalData, ansCursor, 4);
		ansCursor += 4;
	}

	// 保存 responseIPLen
	public void setIPLength() {
		short responseIPLen = (short) 0x0004;
		System.arraycopy(shortToByte(responseIPLen), 0, finalData, ansCursor, 2);
		ansCursor += 2;
	}

	// 保存 responseIP
	public void setResponseIP() throws UnknownHostException {
		byte[] responseIP = InetAddress.getByName(check.ipTable.get(domainNameStr)).getAddress();
		System.arraycopy(responseIP, 0, finalData, ansCursor, 4);
		ansCursor += 4;
	}

	public void remoteDNS() throws IOException {
		outPacket = new DatagramPacket(sendData, sendData.length, InetAddress.getByName(DNS_IP), DNS_PORT);
		socket.send(outPacket);
		System.out.println("转发时间 ：" + new java.util.Date());
		IPv6_Flag = false;

		System.out.println("功能：" + "转发到远端 DNS");

		IDTransition idTransition = new IDTransition((int) byteToShort(sendData), resolverPort, resolverAddress);
		System.out.println("Data : " + idTransition.getID() + "\nPort : " + idTransition.getPort() + "\nAddress : " + idTransition.getAddr());
		System.out.println(Arrays.toString(sendData));
		idMap.put(idTransition.getID(), idTransition);
	}

	public static int byteToInt(byte[] buf, int udpCursor) {
		return buf[udpCursor] & 0xFF;
	}

	public static byte[] intToByte(int s) {
		byte[] targets = new byte[4];
		for (int i = 0; i < 4; i++) {
			int offset = (targets.length - 1 - i) * 8;
			targets[i] = (byte) ((s >>> offset) & 0xff);
		}
		return targets;
	}

	public static String byteToString(byte[] buf, int udpCursor, int length) {
		return new String(buf, udpCursor, length);
	}

	public static byte[] shortToByte(short s) {
		byte[] targets = new byte[2];
		for (int i = 0; i < 2; i++) {
			int offset = (targets.length - 1 - i) * 8;
			targets[i] = (byte) ((s >>> offset) & 0xff);
		}
		return targets;
	}

	public static short byteToShort(byte[] buf) {
		int targets = (buf[0] & 0xff) | ((buf[1] << 8) & 0xff00); // | 表示安位或
		return (short) targets;
	}

	public class IDTransition {
		private int id;
		private int port;
		private InetAddress addr;

		public IDTransition(int id, int port, InetAddress addr) {
			this.id = id;
			this.port = port;
			this.addr = addr;
		}

		public int getID() {
			return id;
		}

		public int getPort() {
			return port;
		}

		public InetAddress getAddr() {
			return addr;
		}
	}

}