# process-injection-via-create-thread

<h1>Malware Development Basics # 1: Process Injection</h1>

<p>Process injection can come in many forms, but one of the most tried and tested ways to inject code into a remote process is via thread creation. This is due to 
the the fact that it is trivial to achieve and very easy to understand. However, with this technique being widely used and trivial to achieve, it's also very easy to detect. 
Despite this I will demonstrate three ways to achieve code injection using threads, via the following means</p>
<ul>
  <li>Winapi Calls</li>
  <li>Native functions</li>
  <li>Sys calls ( another repository most likely) Will add link here</li>
</ul>

<p>This code will act as a stepping stone for people who don't quite grasp the key concepts or people just wishing to learn more. It will be written very clearly 
the naming conventions look a bit disgusting but they make the code incredibly easy to understand. So even if this is out of your understanding, you should at least be able 
to understand what is going on, which is a step in the right direction.</p>
