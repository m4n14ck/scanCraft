require "json"
require "file_utils"

class NmapScanner
  property saved_scans : Hash(String, String)
  property scans_file : String
  property results_dir : String

  def initialize
    @scans_file = "saved_scans.json"
    @results_dir = "scan_results"
    @saved_scans = load_saved_scans
    create_results_dir
  end

  def create_results_dir
    Dir.mkdir_p(@results_dir) unless Dir.exists?(@results_dir)
  end

  def load_saved_scans
    if File.exists?(@scans_file)
      File.open(@scans_file) do |file|
        return Hash(String, String).from_json(file)
      end
    end
    Hash(String, String).new
  end

  def save_scans
    File.write(@scans_file, @saved_scans.to_pretty_json)
  end

  def clear_screen
    system("clear") || system("cls")
  end

  # FUNCION HEX INTEGRADA DIRECTAMENTE
  def hex_color(hex_code : String, text : String) : String
    hex = hex_code.starts_with?('#') ? hex_code[1..] : hex_code
    
    return text unless hex.size == 6
    
    begin
      r = hex[0..1].to_i(16)
      g = hex[2..3].to_i(16)
      b = hex[4..5].to_i(16)
      
      ansi_code = 16 + (36 * (r // 51)) + (6 * (g // 51)) + (b // 51)
      "\e[38;5;#{ansi_code}m#{text}\e[0m"
    rescue
      text
    end
  end

  # Colores usando la funcion HEX con fade azul -> blanco
  def color_dark_blue(text)
    hex_color("#000080", text)  # Azul marino oscuro
  end

  def color_medium_blue(text)
    hex_color("#0000FF", text)  # Azul puro
  end

  def color_light_blue(text)
    hex_color("#4169E1", text)  # Azul real
  end

  def color_sky_blue(text)
    hex_color("#87CEEB", text)  # Azul cielo
  end

  def color_ice_blue(text)
    hex_color("#B0E0E6", text)  # Azul hielo
  end

  def color_white(text)
    hex_color("#FFFFFF", text)  # Blanco puro
  end

  def color_red(text)
    hex_color("#FF0000", text)  # Rojo exacto
  end

  def color_yellow(text)
    hex_color("#FFFF00", text)  # Amarillo exacto
  end

  def color_green(text)
    hex_color("#00FF00", text)  # Verde exacto
  end

  def show_banner
    puts color_medium_blue("  _________                    _________                _____  __   ")
    puts color_medium_blue(" /   _____/ ____ _____    ____ \\_   ___ \\____________ _/ ____\\/  |_ ")
    puts color_sky_blue(" \\_____  \\_/ ___\\\\__  \\  /    \\/    \\  \\/\\_  __ \\__  \\\\   __\\\\   __\\")
    puts color_sky_blue(" /        \\  \\___ / __ \\|   |  \\     \\____|  | \\// __ \\|  |   |  |  ")
    puts color_white("/_______  /\\___  >____  /___|  /\\______  /|__|  (____  /__|   |__|  ")
    puts color_white("        \\/     \\/     \\/     \\/        \\/            \\/              ")
    puts
    puts color_sky_blue("                                  GESTOR DE ESCANEOS NMAP")
    puts color_ice_blue("                                       Made by MAN14CK")
    puts
  end

  # Analizador de resultados Nmap
  def analyze_scan_results(filepath : String)
    analysis = {
      "total_hosts" => 0,
      "hosts_up" => 0,
      "hosts_down" => 0,
      "hosts_filtered" => 0,
      "subnets" => [] of String,
      "services_found" => {} of String => Int32,
      "ports_by_host" => {} of String => Array(Int32),
      "open_ports_total" => 0,
      "filtered_ports_total" => 0,
      "closed_ports_total" => 0,
      "top_services" => [] of String,
      "scan_summary" => ""
    }
    
    return analysis unless File.exists?(filepath)
    
    content = File.read(filepath)
    
    # Contar hosts escaneados
    scan_report_match = content.match(/Nmap scan report for (.+)/)
    if scan_report_match
      analysis["total_hosts"] = content.scan(/Nmap scan report for/).size
    end
    
    # Hosts up
    hosts_up_matches = content.scan(/Host is up/)
    analysis["hosts_up"] = hosts_up_matches.size
    
    # Hosts down (estimado)
    analysis["hosts_down"] = analysis["total_hosts"].as(Int32) - analysis["hosts_up"].as(Int32)
    
    # Extraer subredes unicas
    subnets = Set(String).new
    content.scan(/Nmap scan report for ([\d\.]+)/) do |match|
      ip = match[1]
      # Extraer subred /24
      parts = ip.split('.')
      if parts.size == 4
        subnet = "#{parts[0]}.#{parts[1]}.#{parts[2]}.0/24"
        subnets.add(subnet)
      end
    end
    analysis["subnets"] = subnets.to_a
    
    # Analizar puertos y servicios
    open_ports = 0
    filtered_ports = 0
    closed_ports = 0
    services = Hash(String, Int32).new(0)
    ports_by_host = Hash(String, Array(Int32)).new { [] of Int32 }
    
    current_host = ""
    
    content.each_line do |line|
      # Detectar host actual
      if match = line.match(/Nmap scan report for ([\d\.]+)/)
        current_host = match[1]
      end
      
      # Analizar lineas de puertos
      if line =~ /^\d+\/(tcp|udp)\s+(open|filtered|closed)/
        parts = line.strip.split(/\s+/)
        if parts.size >= 3
          port_info = parts[0].split('/')
          port = port_info[0].to_i? || 0
          state = parts[1]
          service = parts.size >= 4 ? parts[3] : "unknown"
          
          case state
          when "open"
            open_ports += 1
            services[service] += 1
            if current_host != ""
              ports_by_host[current_host] = ports_by_host[current_host] + [port]
            end
          when "filtered"
            filtered_ports += 1
          when "closed"
            closed_ports += 1
          end
        end
      end
      
      # Detectar puertos filtrados especificos
      if line =~ /filtered$/
        filtered_ports += 1
      end
    end
    
    analysis["open_ports_total"] = open_ports
    analysis["filtered_ports_total"] = filtered_ports
    analysis["closed_ports_total"] = closed_ports
    analysis["services_found"] = services
    analysis["ports_by_host"] = ports_by_host
    
    # Top servicios
    top_services = services.to_a.sort_by { |_, count| -count }[0..4].map { |service, _| service }
    analysis["top_services"] = top_services
    
    # Resumen del escaneo
    analysis["scan_summary"] = "Escaneo completo: #{analysis["total_hosts"]} hosts, #{analysis["hosts_up"]} activos, #{open_ports} puertos abiertos"
    
    analysis
  end

  def show_detailed_analysis
    clear_screen
    show_banner
    puts color_light_blue("ANALISIS DETALLADO DE RESULTADOS")
    puts color_light_blue("════════════════════════════════")
    puts
    
    unless Dir.exists?(@results_dir)
      puts color_red("No existe el directorio de resultados.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end
    
    files = Dir.children(@results_dir).select { |f| f.ends_with?(".txt") }
    
    if files.empty?
      puts color_red("No hay resultados guardados para analizar.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end
    
    puts color_white("Resultados disponibles:")
    files.each_with_index do |file, i|
      filepath = File.join(@results_dir, file)
      file_size = File.size(filepath)
      puts color_white("#{i + 1}. #{file}") + color_yellow(" (#{file_size} bytes)")
    end
    puts
    
    print color_light_blue("Selecciona el numero del resultado a analizar (0 para volver): ")
    choice = gets.try(&.chomp) || ""
    
    return if choice == "0"
    
    index = choice.to_i? || -1
    if index < 1 || index > files.size
      puts color_red("Numero invalido.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end
    
    selected_file = files[index - 1]
    filepath = File.join(@results_dir, selected_file)
    
    clear_screen
    show_banner
    puts color_light_blue("ANALISIS DETALLADO: #{selected_file}")
    puts color_light_blue("═" * (30 + selected_file.size))
    puts
    
    analysis = analyze_scan_results(filepath)
    
    # Mostrar estadisticas generales
    puts color_medium_blue("ESTADISTICAS GENERALES")
    puts color_medium_blue("══════════════════════")
    puts
    
    total_hosts = analysis["total_hosts"].as(Int32)
    hosts_up = analysis["hosts_up"].as(Int32)
    hosts_down = analysis["hosts_down"].as(Int32)
    open_ports = analysis["open_ports_total"].as(Int32)
    filtered_ports = analysis["filtered_ports_total"].as(Int32)
    closed_ports = analysis["closed_ports_total"].as(Int32)
    
    puts color_white("Total de hosts escaneados: ") + color_yellow(total_hosts.to_s)
    puts color_white("Hosts activos (up): ") + color_green(hosts_up.to_s)
    puts color_white("Hosts inactivos (down): ") + color_red(hosts_down.to_s)
    puts
    
    puts color_white("Puertos abiertos: ") + color_green(open_ports.to_s)
    puts color_white("Puertos filtrados: ") + color_yellow(filtered_ports.to_s)
    puts color_white("Puertos cerrados: ") + color_red(closed_ports.to_s)
    puts
    
    # Mostrar subredes analizadas
    subnets = analysis["subnets"].as(Array(String))
    if subnets.any?
      puts color_medium_blue("SUBREDES ANALIZADAS")
      puts color_medium_blue("═══════════════════")
      puts
      subnets.each do |subnet|
        puts color_white("  • ") + color_light_blue(subnet)
      end
      puts
    end
    
    # Mostrar servicios encontrados
    services = analysis["services_found"].as(Hash(String, Int32))
    if services.any?
      puts color_medium_blue("SERVICIOS DETECTADOS")
      puts color_medium_blue("════════════════════")
      puts
      
      services.to_a.sort_by { |_, count| -count }.each do |service, count|
        if count > 0
          puts color_white("  #{service}: ") + color_yellow(count.to_s)
        end
      end
      puts
    end
    
    # Mostrar top servicios
    top_services = analysis["top_services"].as(Array(String))
    if top_services.any?
      puts color_medium_blue("TOP SERVICIOS MAS COMUNES")
      puts color_medium_blue("═════════════════════════")
      puts
      top_services.each_with_index do |service, i|
        puts color_white("  #{i + 1}. ") + color_green(service)
      end
      puts
    end
    
    # Mostrar hosts con puertos abiertos
    ports_by_host = analysis["ports_by_host"].as(Hash(String, Array(Int32)))
    if ports_by_host.any?
      puts color_medium_blue("HOSTS CON PUERTOS ABIERTOS")
      puts color_medium_blue("══════════════════════════")
      puts
      
      ports_by_host.each do |host, ports|
        port_list = ports.sort
        if port_list.any?
          puts color_white("#{host}: ") + color_green(port_list.join(", "))
        end
      end
      puts
    end
    
    # Resumen ejecutivo
    puts color_medium_blue("RESUMEN EJECUTIVO")
    puts color_medium_blue("═════════════════")
    puts
    
    if total_hosts > 0
      uptime_percentage = (hosts_up.to_f / total_hosts * 100).round(2)
      puts color_white("Tasa de hosts activos: ") + color_green("#{uptime_percentage}%")
    end
    
    if hosts_up > 0
      ports_per_host = (open_ports.to_f / hosts_up).round(2)
      puts color_white("Promedio de puertos abiertos por host: ") + color_yellow(ports_per_host.to_s)
    end
    
    # Recomendaciones de seguridad
    puts
    puts color_medium_blue("RECOMENDACIONES DE SEGURIDAD")
    puts color_medium_blue("═══════════════════════════")
    puts
    
    if open_ports == 0
      puts color_green("✓ Excelente! No se encontraron puertos abiertos.")
    else
      puts color_yellow("⚠ Se encontraron #{open_ports} puertos abiertos que requieren atencion:")
      
      services.each do |service, count|
        service_name = service
        service_count = count
        
        case service_name
        when "ssh"
          puts color_white("  • SSH (#{service_count} instancias): ") + color_yellow("Asegurar configuracion y usar claves SSH")
        when "http"
          puts color_white("  • HTTP (#{service_count} instancias): ") + color_yellow("Considerar migrar a HTTPS")
        when "ftp"
          puts color_white("  • FTP (#{service_count} instancias): ") + color_red("Protocolo inseguro, usar SFTP o FTPS")
        when "telnet"
          puts color_white("  • Telnet (#{service_count} instancias): ") + color_red("Protocolo muy inseguro, deshabilitar inmediatamente")
        when "mysql", "postgresql"
          puts color_white("  • #{service_name.upcase} (#{service_count} instancias): ") + color_yellow("Asegurar acceso y cambiar credenciales por defecto")
        end
      end
    end
    
    if filtered_ports > 0
      puts color_white("  • #{filtered_ports} puertos filtrados: ") + 
           color_sky_blue("Firewall activo detectado")
    end
    
    puts
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def show_network_info
    clear_screen
    show_banner
    puts color_light_blue("INFORMACION DE RED")
    puts color_light_blue("═══════════════════")
    puts
    
    puts color_white("Selecciona una opcion para ver la informacion de red:")
    puts color_white("  1. Mostrar interfaces de red (ip a)")
    puts color_white("  2. Mostrar interfaces de red (ifconfig)")
    puts color_white("  3. Mostrar tabla de rutas")
    puts color_white("  4. Mostrar conexiones establecidas")
    puts color_white("  5. Verificar conectividad a internet")
    puts
    
    print color_light_blue("Selecciona una opcion (1-5): ")
    choice = gets.try(&.chomp) || ""

    case choice
    when "1"
      clear_screen
      show_banner
      puts color_light_blue("INTERFACES DE RED - ip a")
      puts color_light_blue("═════════════════════════")
      puts
      system("ip a")
    when "2"
      clear_screen
      show_banner
      puts color_light_blue("INTERFACES DE RED - ifconfig")
      puts color_light_blue("════════════════════════════")
      puts
      system("ifconfig")
    when "3"
      clear_screen
      show_banner
      puts color_light_blue("TABLA DE RUTAS")
      puts color_light_blue("══════════════")
      puts
      system("ip route")
    when "4"
      clear_screen
      show_banner
      puts color_light_blue("CONEXIONES ESTABLECIDAS")
      puts color_light_blue("═══════════════════════")
      puts
      system("ss -tuln")
    when "5"
      clear_screen
      show_banner
      puts color_light_blue("VERIFICAR CONECTIVIDAD A INTERNET")
      puts color_light_blue("═════════════════════════════════")
      puts
      puts color_white("Verificando conectividad a internet...")
      puts color_sky_blue("═" * 50)
      puts
      system("ping -c 3 8.8.8.8")
      puts
      puts color_sky_blue("═" * 50)
      puts color_green("Verificacion completada")
    else
      puts color_red("Opcion no valida")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end
    
    puts
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def validate_scan_params(params : String) : Bool
    if params.downcase.includes?("nmap")
      puts color_red("Error: No incluyas 'nmap' en los parametros.")
      puts color_yellow("Solo ingresa los parametros como: -sS -sV -Pn")
      return false
    end

    ip_pattern = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?:-\d{1,3})?\b/
    if params =~ ip_pattern
      puts color_red("Error: No incluyas la IP en los parametros.")
      puts color_yellow("La IP se pedira al momento de ejecutar el escaneo.")
      return false
    end

    unless params.strip.starts_with?('-')
      puts color_red("Error: Los parametros deben empezar con '-'")
      puts color_yellow("Ejemplo: -sS -sV -Pn -vv")
      return false
    end

    true
  end

  def create_custom_scan
    clear_screen
    show_banner
    puts color_medium_blue("CREAR COMANDO NMAP")
    puts color_medium_blue("══════════════════")
    puts
    
    puts color_white("Ingresa solo los parametros de Nmap (sin 'nmap' ni la IP):")
    puts color_white("Ejemplos:")
    puts color_white("  -sS -sV -Pn -vv -T2")
    puts color_white("  -sS -sV -O -A") 
    puts color_white("  --script vuln -p 80,443")
    puts color_white("  -sU -T4 -p 53,67,68,69,123,161,162,514")
    puts

    scan_params = ""
    loop do
      print color_light_blue("Parametros Nmap: ")
      scan_params = gets.try(&.chomp) || ""

      if scan_params.empty?
        puts color_red("Los parametros no pueden estar vacios.")
        next
      end

      break if validate_scan_params(scan_params)
    end

    scan_name = ""
    loop do
      print color_light_blue("Nombre corto (sin espacios): ")
      scan_name = gets.try(&.chomp) || ""

      if scan_name.empty?
        puts color_red("El nombre no puede estar vacio.")
        next
      end

      if scan_name.includes?(' ')
        puts color_red("El nombre no puede contener espacios.")
        next
      end

      if @saved_scans.has_key?(scan_name)
        puts color_red("Ya existe un escaneo con ese nombre!")
        next
      end

      break
    end

    unless scan_params.starts_with?(" ")
      scan_params = " " + scan_params
    end

    @saved_scans[scan_name] = scan_params
    save_scans
    puts color_green("Comando '#{scan_name}' guardado exitosamente!")
    puts color_white("Comando completo: ") + color_green("nmap#{scan_params} {ip}")
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def list_saved_scans
    clear_screen
    show_banner
    puts color_medium_blue("COMANDOS GUARDADOS")
    puts color_medium_blue("══════════════════")
    puts
    
    if @saved_scans.empty?
      puts color_red("No hay comandos guardados.")
    else
      @saved_scans.each_with_index do |(name, params), i|
        puts color_white("#{i + 1}. #{name}: ") + color_yellow("nmap#{params} {ip}")
      end
    end
    
    puts
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def execute_scan
    clear_screen
    show_banner
    puts color_light_blue("EJECUTAR ESCANEO")
    puts color_light_blue("═════════════════")
    puts
    
    if @saved_scans.empty?
      puts color_red("No hay comandos guardados.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    puts color_white("Comandos guardados:")
    commands_list = [] of String
    @saved_scans.each_with_index do |(name, params), i|
      puts color_white("#{i + 1}. #{name}: ") + color_yellow("nmap#{params} {ip}")
      commands_list << name
    end
    puts
    
    print color_light_blue("Selecciona el numero del escaneo a ejecutar: ")
    choice = gets.try(&.chomp) || ""

    if choice.empty?
      puts color_red("Debes seleccionar un numero.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    index = choice.to_i? || -1
    if index < 1 || index > commands_list.size
      puts color_red("Numero de escaneo invalido.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    scan_name = commands_list[index - 1]
    scan_params = @saved_scans[scan_name]

    print color_light_blue("IP objetivo o direccion de red (ej: 192.168.1.1, 10.0.0.0/24, 172.16.1.1-100): ")
    target_ip = gets.try(&.chomp) || ""

    if target_ip.empty?
      puts color_red("Debes ingresar una IP o direccion de red.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    final_command = "nmap#{scan_params} #{target_ip}"

    puts color_white("\nResumen del escaneo:")
    puts color_white("  Nombre: ") + color_green(scan_name)
    puts color_white("  Objetivo: ") + color_green(target_ip)
    puts color_white("  Comando: ") + color_green(final_command)
    puts color_sky_blue("═" * 50)
    
    print color_yellow("Ejecutar este comando? (s/n): ")
    confirm = gets.try(&.chomp) || ""

    if confirm.downcase == "s" || confirm.downcase == "si"
      clear_screen
      show_banner
      puts color_light_blue("EJECUTANDO ESCANEO")
      puts color_light_blue("══════════════════")
      puts
      
      puts color_white("Escaneo: ") + color_green(scan_name)
      puts color_white("Objetivo: ") + color_green(target_ip)
      puts color_white("Comando: ") + color_green(final_command)
      puts color_sky_blue("═" * 50)
      puts

      # Crear archivo temporal para capturar la salida
      temp_file = File.tempfile("nmap_scan")
      
      scan_completed = false
      scan_interrupted = false

      begin
        # Ejecutar el comando y capturar salida en archivo temporal Y mostrarla en pantalla
        exit_status = Process.run("#{final_command} | tee #{temp_file.path}", 
          shell: true, 
          input: Process::Redirect::Close,
          output: Process::Redirect::Inherit,
          error: Process::Redirect::Inherit
        )
        
        if exit_status.normal_exit?
          scan_completed = true
          puts
          puts color_sky_blue("═" * 50)
          puts color_green("Escaneo completado exitosamente!")
          
          # Ofrecer guardar los resultados que YA tenemos
          puts
          print color_yellow("¿Deseas guardar los resultados de este escaneo? (s/n): ")
          save_choice = gets.try(&.chomp) || ""
          
          if save_choice.downcase == "s" || save_choice.downcase == "si"
            save_scan_results_from_temp(scan_name, target_ip, temp_file.path)
          end
        else
          puts
          puts color_sky_blue("═" * 50)
          puts color_yellow("Escaneo terminado con codigo de salida: #{exit_status.exit_code}")
        end

        # Limpiar archivo temporal
        temp_file.delete

      rescue ex : IO::Error
        # Esto captura interrupciones como Ctrl+C
        scan_interrupted = true
        puts
        puts color_sky_blue("═" * 50)
        puts color_red("Escaneo interrumpido por el usuario")
        temp_file.delete
      end

      puts color_yellow("Presiona Enter para volver al menu...")
      gets
    else
      puts color_red("Ejecucion cancelada.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
    end
  end

  def save_scan_results_from_temp(scan_name : String, target_ip : String, temp_file_path : String)
    clear_screen
    show_banner
    puts color_green("GUARDAR RESULTADOS DEL ESCANEO")
    puts color_green("══════════════════════════════")
    puts
    
    puts color_white("Escaneo: ") + color_yellow(scan_name)
    puts color_white("Objetivo: ") + color_yellow(target_ip)
    puts
    
    timestamp = Time.local.to_s("%Y%m%d_%H%M%S")
    safe_target = target_ip.gsub(/[\/:-]/, "_")
    default_filename = "#{scan_name}_#{safe_target}_#{timestamp}.txt"
    
    print color_light_blue("Nombre del archivo para guardar resultados [#{default_filename}]: ")
    filename = gets.try(&.chomp) || default_filename
    
    unless filename.includes?('.')
      filename += ".txt"
    end
    
    filepath = File.join(@results_dir, filename)
    
    # Copiar el contenido del archivo temporal al archivo final
    FileUtils.cp(temp_file_path, filepath)
    
    puts
    puts color_green("Resultados guardados exitosamente en: #{filepath}")
    
    if File.exists?(filepath)
      file_size = File.size(filepath)
      puts color_white("Tamaño del archivo: ") + color_yellow("#{file_size} bytes")
    end
    
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def view_saved_results
    clear_screen
    show_banner
    puts color_light_blue("RESULTADOS GUARDADOS")
    puts color_light_blue("════════════════════")
    puts
    
    unless Dir.exists?(@results_dir)
      puts color_red("No existe el directorio de resultados.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end
    
    files = Dir.children(@results_dir).select { |f| f.ends_with?(".txt") }
    
    if files.empty?
      puts color_red("No hay resultados guardados.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end
    
    puts color_white("Resultados disponibles:")
    files.each_with_index do |file, i|
      filepath = File.join(@results_dir, file)
      file_size = File.size(filepath)
      puts color_white("#{i + 1}. #{file}") + color_yellow(" (#{file_size} bytes)")
    end
    puts
    
    print color_light_blue("Selecciona el numero del resultado a ver (0 para volver): ")
    choice = gets.try(&.chomp) || ""
    
    return if choice == "0"
    
    index = choice.to_i? || -1
    if index < 1 || index > files.size
      puts color_red("Numero invalido.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end
    
    selected_file = files[index - 1]
    filepath = File.join(@results_dir, selected_file)
    
    clear_screen
    show_banner
    puts color_light_blue("VIENDO RESULTADOS: #{selected_file}")
    puts color_light_blue("═" * (30 + selected_file.size))
    puts
    
    if File.exists?(filepath)
      content = File.read_lines(filepath)
      if content.size > 100
        content.first(100).each { |line| puts line }
        puts
        puts color_yellow("... (archivo muy grande, mostrando solo primeras 100 lineas)")
        puts color_yellow("Usa 'cat #{filepath}' para ver el archivo completo")
      else
        content.each { |line| puts line }
      end
    else
      puts color_red("El archivo no existe.")
    end
    
    puts
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def delete_scan
    clear_screen
    show_banner
    puts color_medium_blue("ELIMINAR COMANDO")
    puts color_medium_blue("════════════════")
    puts
    
    if @saved_scans.empty?
      puts color_red("No hay comandos guardados.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    puts color_white("Comandos guardados:")
    commands_list = [] of String
    @saved_scans.each_with_index do |(name, params), i|
      puts color_white("#{i + 1}. #{name}: ") + color_yellow("nmap#{params} {ip}")
      commands_list << name
    end
    puts
    
    print color_light_blue("Selecciona el numero del comando a eliminar: ")
    choice = gets.try(&.chomp) || ""

    if choice.empty?
      puts color_red("Debes seleccionar un numero.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    index = choice.to_i? || -1
    if index < 1 || index > commands_list.size
      puts color_red("Numero de comando invalido.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    scan_name = commands_list[index - 1]

    print color_red("Estas seguro de eliminar '#{scan_name}'? (s/n): ")
    confirm = gets.try(&.chomp) || ""

    if confirm.downcase == "s" || confirm.downcase == "si"
      @saved_scans.delete(scan_name)
      save_scans
      puts color_green("Comando '#{scan_name}' eliminado!")
    else
      puts color_yellow("Eliminacion cancelada.")
    end
    
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def edit_scan
    clear_screen
    show_banner
    puts color_sky_blue("EDITAR COMANDO")
    puts color_sky_blue("══════════════")
    puts
    
    if @saved_scans.empty?
      puts color_red("No hay comandos guardados.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    puts color_white("Comandos guardados:")
    commands_list = [] of String
    @saved_scans.each_with_index do |(name, params), i|
      puts color_white("#{i + 1}. #{name}: ") + color_yellow("nmap#{params} {ip}")
      commands_list << name
    end
    puts
    
    print color_light_blue("Selecciona el numero del comando a editar: ")
    choice = gets.try(&.chomp) || ""

    if choice.empty?
      puts color_red("Debes seleccionar un numero.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    index = choice.to_i? || -1
    if index < 1 || index > commands_list.size
      puts color_red("Numero de comando invalido.")
      puts color_yellow("Presiona Enter para continuar...")
      gets
      return
    end

    scan_name = commands_list[index - 1]

    puts color_white("Parametros actual: ") + color_yellow(@saved_scans[scan_name])
    puts color_white("Ingresa los nuevos parametros (sin 'nmap' ni IP):")
    
    new_params = ""
    loop do
      print color_light_blue("Nuevos parametros: ")
      new_params = gets.try(&.chomp) || ""

      if new_params.empty?
        puts color_red("Los parametros no pueden estar vacios.")
        next
      end

      break if validate_scan_params(new_params)
    end

    unless new_params.starts_with?(" ")
      new_params = " " + new_params
    end

    @saved_scans[scan_name] = new_params
    save_scans
    puts color_green("Comando '#{scan_name}' actualizado!")
    puts color_white("Nuevo comando: ") + color_green("nmap#{new_params} {ip}")
    
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def export_config
    clear_screen
    show_banner
    puts color_sky_blue("EXPORTAR CONFIGURACION")
    puts color_sky_blue("══════════════════════")
    puts
    
    print color_light_blue("Nombre del archivo para exportar: ")
    export_file = gets.try(&.chomp) || "scans_backup.json"

    File.write(export_file, @saved_scans.to_pretty_json)
    puts color_green("Configuracion exportada a '#{export_file}'!")
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def import_config
    clear_screen
    show_banner
    puts color_ice_blue("IMPORTAR CONFIGURACION")
    puts color_ice_blue("══════════════════════")
    puts
    
    print color_light_blue("Nombre del archivo para importar: ")
    import_file = gets.try(&.chomp) || "scans_backup.json"

    if File.exists?(import_file)
      File.open(import_file) do |file|
        imported_scans = Hash(String, String).from_json(file)
        @saved_scans.merge!(imported_scans)
        save_scans
        puts color_green("#{imported_scans.size} comandos importados!")
      end
    else
      puts color_red("El archivo '#{import_file}' no existe.")
    end
    
    puts color_yellow("Presiona Enter para continuar...")
    gets
  end

  def show_stats
    clear_screen
    show_banner
    puts color_white("ESTADISTICAS")
    puts color_white("═════════════")
    puts
    
    # Estadísticas básicas mejoradas
    total_commands = @saved_scans.size
    puts color_medium_blue("COMANDOS GUARDADOS")
    puts color_medium_blue("══════════════════")
    puts color_white("Total de comandos: ") + color_yellow(total_commands.to_s)
    
    if total_commands > 0
      # Comando más usado (más corto)
      shortest_command = @saved_scans.values.min_by(&.size)
      longest_command = @saved_scans.values.max_by(&.size)
      
      puts color_white("Comando mas corto: ") + color_green(shortest_command.size.to_s + " caracteres")
      puts color_white("Comando mas largo: ") + color_yellow(longest_command.size.to_s + " caracteres")
      
      # Promedio de longitud de comandos
      avg_length = @saved_scans.values.sum(&.size) / total_commands
      puts color_white("Longitud promedio: ") + color_sky_blue(avg_length.to_s + " caracteres")
      
      # Últimos 3 comandos agregados
      puts color_white("\nUltimos comandos agregados:")
      @saved_scans.first(3).each_with_index do |(name, params), i|
        puts color_white("  #{i + 1}. #{name}: ") + color_ice_blue("nmap#{params}")
      end
    end
    
    puts
    puts color_medium_blue("RESULTADOS GUARDADOS")
    puts color_medium_blue("════════════════════")
    
    if Dir.exists?(@results_dir)
      result_files = Dir.children(@results_dir).select { |f| f.ends_with?(".txt") }
      total_results = result_files.size
      
      if total_results > 0
        puts color_white("Total de resultados: ") + color_green(total_results.to_s)
        
        total_size = result_files.sum { |f| File.size(File.join(@results_dir, f)) }
        puts color_white("Espacio total usado: ") + color_yellow("#{total_size} bytes")
        
        # Archivo más reciente
        latest_file = result_files.max_by? { |f| File.info(File.join(@results_dir, f)).modification_time }
        if latest_file
          mod_time = File.info(File.join(@results_dir, latest_file)).modification_time
          puts color_white("Archivo mas reciente: ") + color_green(latest_file)
          puts color_white("Fecha de modificacion: ") + color_sky_blue(mod_time.to_s("%Y-%m-%d %H:%M"))
        end
        
        # Tamaño del archivo más grande
        largest_file = result_files.max_by? { |f| File.size(File.join(@results_dir, f)) }
        if largest_file
          largest_size = File.size(File.join(@results_dir, largest_file))
          puts color_white("Archivo mas grande: ") + color_yellow("#{largest_file} (#{largest_size} bytes)")
        end
      else
        puts color_red("No hay resultados guardados")
      end
    else
      puts color_red("Directorio de resultados no existe")
    end
    
    puts
    puts color_medium_blue("INFORMACION DEL SISTEMA")
    puts color_medium_blue("═══════════════════════")
    
    # Información básica del sistema
    if Dir.exists?(@results_dir)
      result_files = Dir.children(@results_dir).select { |f| f.ends_with?(".txt") }
      total_results = result_files.size
      
      puts color_white("Archivo de configuracion: ") + color_sky_blue(@scans_file)
      puts color_white("Directorio de resultados: ") + color_sky_blue(@results_dir)
      puts color_white("Total de archivos de datos: ") + color_yellow((total_commands > 0 ? 1 : 0).to_s + " (comandos) + " + total_results.to_s + " (resultados)")
    end
    
    puts
    puts color_white("OPCIONES AVANZADAS:")
    puts color_white("  1. ") + color_green("Ver estas estadisticas basicas")
    puts color_white("  2. ") + color_light_blue("Analisis detallado de resultados")
    puts
    
    print color_light_blue("Selecciona una opcion (1-2): ")
    choice = gets.try(&.chomp) || "1"
    
    case choice
    when "2"
      show_detailed_analysis
    else
      # Cuando selecciona 1, ya mostramos las estadísticas, solo esperamos Enter
      puts
      puts color_yellow("Presiona Enter para volver al menu principal...")
      gets
    end
  end

  def show_menu
    loop do
      clear_screen
      show_banner
      
      puts color_white("  Bienvenido a la herramienta de escaneos Nmap")
      puts color_white("  Selecciona una opcion para continuar")
      puts
      puts color_sky_blue("═══════════════════════════════════════════════")
      puts
      puts color_light_blue("   [1] Crear comando Nmap")
      puts color_light_blue("   [2] Ver comandos guardados")
      puts color_light_blue("   [3] Ejecutar escaneo")
      puts color_light_blue("   [4] Informacion de red")
      puts color_white("   [5] Eliminar comando")
      puts color_white("   [6] Editar comando")
      puts color_light_blue("   [7] Exportar configuracion")
      puts color_light_blue("   [8] Importar configuracion")
      puts color_light_blue("   [9] Ver resultados guardados")
      puts color_light_blue("   [10] Estadisticas y Analisis")
      puts color_red("   [0] Salir")
      puts
      puts color_sky_blue("═══════════════════════════════════════════════")
      puts

      print color_light_blue("  Selecciona una opcion >>> ")
      choice = gets.try(&.chomp) || ""

      case choice
      when "1"
        create_custom_scan
      when "2"
        list_saved_scans
      when "3"
        execute_scan
      when "4"
        show_network_info
      when "5"
        delete_scan
      when "6"
        edit_scan
      when "7"
        export_config
      when "8"
        import_config
      when "9"
        view_saved_results
      when "10"
        show_stats
      when "0"
        clear_screen
        puts color_light_blue("Hasta luego!")
        break
      else
        puts color_red("Opcion no valida")
        puts color_yellow("Presiona Enter para continuar...")
        gets
      end
    end
  end
end

# Ejecutar la aplicacion
scanner = NmapScanner.new
scanner.show_menu
