<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  version="1.0">

  <!-- Output method -->
  <xsl:output method="html"
            encoding="iso-8859-1"
              indent="yes"/>


  <!-- Defined parameters (overrideable) -->
  <xsl:param    name="relative-path" select="'.'"/>

  <!-- Process an entire document into an HTML page -->
  <xsl:template match="modulesynopsis">

    <html>

<!-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        This file is generated from xml source: DO NOT EDIT
     XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX -->

    <head>
      <xsl:apply-templates select="meta"/>
      <title><xsl:value-of select="name"/> - Apache HTTP Server</title>
      <link rel="stylesheet" type="text/css" href="../style/manual.css" />
    </head>
    <body>

<blockquote>

    <div align="center">
      <img src="../images/sub.gif" alt="[APACHE DOCUMENTATION]" /> 
      <h3>Apache HTTP Server Version 2.0</h3>
    </div>
    <h1 align="center">Apache Module <xsl:value-of select="name"/></h1>

<!-- Description and module-headers -->


<table bgcolor="#cccccc" cellpadding="0" cellspacing="1">
<tr><td>
<table bgcolor="#ffffff">
<tr><td><span class="help">Description:</span> </td>
<td><xsl:apply-templates select="description"/></td></tr>
<tr><td><a class="help" href="module-dict.html#Status">Status:</a> </td>
<td><xsl:value-of select="status"/></td></tr>
<tr><td><a class="help" href="module-dict.html#ModuleIdentifier">Module&nbsp;Identifier:</a> </td>
<td><xsl:value-of select="identifier"/></td></tr>
<xsl:if test="compatibility">
<tr><td><a class="help" href="module-dict.html#Compatibility">Compatibility:</a> </td>
<td><xsl:apply-templates select="compatibility"/></td></tr>
</xsl:if>
</table>
</td></tr>
</table>


<h2>Summary</h2>
<xsl:apply-templates select="summary"/>

<xsl:if test="seealso">
<p><strong>See also:</strong></p>
<ul>
  <xsl:for-each select="seealso">
    <li><xsl:apply-templates/></li>
  </xsl:for-each>
</ul>
</xsl:if>

<h2>Directives</h2>

<ul>
 <xsl:for-each select="directivesynopsis/name">
  <xsl:sort select="name"/>
  <xsl:variable name="name">
   <xsl:value-of select="."/>
  </xsl:variable>
  <li><a href="#{$name}"><xsl:value-of select="."/></a></li>
 </xsl:for-each>
</ul>

<xsl:apply-templates select="section"/>

<hr />

<xsl:apply-templates select="directivesynopsis">
  <xsl:sort select="name"/>
</xsl:apply-templates> 

    <h3 align="center">Apache HTTP Server Version 2.0</h3>
    <a href="./"><img src="../images/index.gif" alt="Index" /></a>
    <a href="../"><img src="../images/home.gif" alt="Home" /></a>

</blockquote>

    </body>
    </html>
  </xsl:template>

<!-- Process a documentation section -->
  <xsl:template match="section">
    <xsl:variable name="href">
      <xsl:value-of select="@id"/>
    </xsl:variable>
      <!-- Section heading -->
    <xsl:if test="@id">
      <h2><a name="{$href}"><xsl:apply-templates select="./title" mode="print"/></a></h2>
    </xsl:if>
    <xsl:if test="not(@id)">
      <h2><xsl:apply-templates select="./title" mode="print"/></h2>
    </xsl:if>
      <!-- Section body -->
        <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="section/title" mode="print">
    <xsl:apply-templates/>
  </xsl:template>

  <!-- Don't print the title twice -->
  <xsl:template match="section/title"></xsl:template>

  <xsl:template match="directivesynopsis">
  <xsl:variable name="name">
   <xsl:value-of select="./name"/>
  </xsl:variable>

    <h2><a name="{$name}"><xsl:value-of select="./name"/> Directive</a></h2>
<table bgcolor="#cccccc" border="0" cellspacing="0" cellpadding="1">
<tr><td>
<table bgcolor="#ffffff" width="100%">
<tr><td>Description: </td>
<td><xsl:value-of select="description"/></td></tr>
<tr><td><a class="help" href="directive-dict.html#Syntax">Syntax:</a> </td>
<td><xsl:apply-templates select="syntax"/></td></tr>
<xsl:if test="default">
<tr><td><a class="help" href="directive-dict.html#Default">Default:</a> </td>
<td><code><xsl:value-of select="default"/></code></td></tr>
</xsl:if>
<tr><td><a class="help" href="directive-dict.html#Context">Context:</a> </td>
<td><xsl:apply-templates select="contextlist"/></td></tr>
<xsl:if test="override">
<tr><td><a class="help" href="directive-dict.html#Override">Override:</a> </td>
<td><xsl:value-of select="override"/></td></tr>
</xsl:if>
<tr><td><a class="help" href="directive-dict.html#Status">Status:</a> </td>
<td><xsl:value-of select="/modulesynopsis/status"/></td></tr>
<tr><td><a class="help" href="directive-dict.html#Module">Module:</a> </td>
<td><xsl:value-of select="/modulesynopsis/name"/></td></tr>
<xsl:if test="compatibility">
<tr><td><a class="help" href="directive-dict.html#Compatibility">Compatibility:</a> </td>
<td><xsl:value-of select="compatibility"/></td></tr>
</xsl:if>
</table>
</td></tr></table>
<xsl:apply-templates select="usage"/>

<xsl:if test="seealso">
<p><strong>See also:</strong></p>
<ul>
  <xsl:for-each select="seealso">
    <li><xsl:apply-templates/></li>
  </xsl:for-each>
</ul>
</xsl:if>

<hr />
</xsl:template>

  <xsl:template match="contextlist">
    <xsl:apply-templates select="context"/>
  </xsl:template>

  <xsl:template match="context">
    <xsl:value-of select="." />
    <xsl:if test="not(position()=last())">, </xsl:if>
  </xsl:template>

  <xsl:template match="example">
  <blockquote>
  <table cellpadding="10"><tr><td bgcolor="#eeeeee">
     <xsl:apply-templates select="title" mode="print"/>
     <code><xsl:apply-templates/></code>
  </td></tr></table>
  </blockquote>
  </xsl:template>

  <xsl:template match="example/title" mode="print">
     <p align="center"><strong><xsl:apply-templates/></strong></p>
  </xsl:template>
  <xsl:template match="example/title"></xsl:template>

  <xsl:template match="note">
  <blockquote>
  <table><tr><td bgcolor="#ffffcc">
     <xsl:apply-templates/>
  </td></tr></table>
  </blockquote>
  </xsl:template>
  <xsl:template match="note/title">
     <p align="center"><strong><xsl:apply-templates/></strong></p>
  </xsl:template>

  <xsl:template match="directive">
    <code class="directive">
    <xsl:if test="@module">
      <xsl:variable name="module">
        <xsl:value-of select="./@module"/>
      </xsl:variable>
      <xsl:variable name="directive">
        <xsl:value-of select="."/>
      </xsl:variable>
      <xsl:if test="@module=/modulesynopsis/name">
        <a class="directive" href="#{$directive}"><xsl:value-of select="."/></a>
      </xsl:if>
      <xsl:if test="@module!=/modulesynopsis/name">
        <a class="directive" href="{$module}.html#{$directive}"><xsl:value-of select="."/></a>
      </xsl:if>
    </xsl:if>
    <xsl:if test="not(@module)">
       <xsl:value-of select="."/>
    </xsl:if>
    </code>
  </xsl:template>

  <xsl:template match="module">
    <code>
    <xsl:variable name="href">
      <xsl:value-of select="."/>
    </xsl:variable>
    <a href="{$href}.html"><xsl:value-of select="."/></a>
    </code>
  </xsl:template>

  <!-- Process everything else by just passing it through -->
  <xsl:template match="*|@*">
    <xsl:copy>
      <xsl:apply-templates select="@*|*|text()"/>
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
