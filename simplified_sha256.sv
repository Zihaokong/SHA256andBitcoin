module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[16]; 
//word expansion

logic [31:0] message[16*((((NUM_OF_WORDS >> 4) << 4) == NUM_OF_WORDS) ? NUM_OF_WORDS >> 4 : (NUM_OF_WORDS >> 4) + 1 )];
//at instantiation determine the message size.

logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [31:0] S0,S1;
//hasing algorithm needs.

logic [ 7:0] i, j;
//calculating iteration and current messge block

logic [15:0] offset; 
//mem reading and mem writing

logic [ 7:0] num_blocks;
//number of 512-bit blocks in input message

logic        cur_we;
//memory write enable

logic [15:0] cur_addr;
//pointer to memory, for reading and writing

logic [31:0] cur_write_data;
//data to write in memory

logic [ 7:0] tstep;


// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
//determine number of blocks using functions.

assign tstep = (i - 1);

// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);
	determine_num_blocks = (((size >> 4) << 4) == size) ? size >> 4 : (size >> 4) + 1 ;
	//integer division by 16.
endfunction


//hasing algorithm
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ (~e & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
	return (x >> r) | (x << (32-r));
endfunction

function logic [31:0] wtnews;
	logic [31:0] s0,s1;
	s0 = rightrotate(w[1],7) ^ rightrotate(w[1],18) ^ (w[1]>>3);
	s1 = rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10);
	wtnews = w[0] + s0 + w[9] + s1;
endfunction
					
// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;



// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
		 // Initialize variables
		 h0 <= 32'h6a09e667;
		 h1 <= 32'hbb67ae85;
		 h2 <= 32'h3c6ef372;
		 h3 <= 32'ha54ff53a;
		 h4 <= 32'h510e527f;
		 h5 <= 32'h9b05688c;
		 h6 <= 32'h1f83d9ab;
		 h7 <= 32'h5be0cd19;
		 
		 a<=0;
		 b<=0;
		 c<=0;
		 d<=0;
		 e<=0;
		 f<=0;
		 g<=0;
		 h<=0;
		 
		 S0 <= 0;
		 S1 <= 0;
		 
		 i <= 0;
		 j <= 0;
		 
		 offset <= 0;
		 cur_we <= 0;
		 cur_addr <= message_addr;
		 cur_write_data <= 0;
		 
		 //initialize message block to be 0 as well;
		 for(int k = 0; k < 32;k ++) begin
			message[k] <= 0;
		 end
		 
		 //state change based on start signal.
       if(start) state <= READ;
		 else state <= IDLE;
    end

	 // Read data from memory 
	 READ: begin
		//reading all input message
		if (offset <= NUM_OF_WORDS) begin
			//waiting for one clock cycle.
			if (offset != 0) message[offset-1] <= mem_read_data;
			
			offset <= offset + 1;
			state <= READ;
		end
		
		// finished reading all the data
		else begin
			offset <= 0;
			
			//padding bit 1,
			message[NUM_OF_WORDS] <= 32'b10000000000000000000000000000000;
			
			//padding message length into last 64 bits;
			{message[num_blocks*16-2],message[num_blocks*16-1]} <= NUM_OF_WORDS * 32;
			
			state <= BLOCK;
		end
	 end
	 
	 
    BLOCK: begin
		i <= 0;
		//processing all 512 blocks based on num_blocks 
		if (j < num_blocks) begin
			state <= COMPUTE;
			//initialize a to h
			{a,b,c,d,e,f,g,h} <= {h0,h1,h2,h3,h4,h5,h6,h7};
		end
		else begin
		
			//finish processing blocks, writing to memory.
			j <= 0;
			state <= WRITE;
		end
    end

    COMPUTE: begin
		  // 64 processing rounds steps for 512-bit block 
        if (i <= 64) begin
				// word expansion
				if (i < 16) begin
					w[i] <= message[i+j*16];
					$display("%h",w[i-1]);
				end
				else begin
					for(int n = 0; n < 15; n ++) w[n] <= w[n+1];
					w[15] <= wtnews();
					$display("%h",w[15]);
					
				end
				
				if(i > 0 && i <= 16) {a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h,w[i-1],i-1);
				else if(i>16) {a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h,w[15],i-1);
				i <= i + 1;
				state <= COMPUTE;
			end
			else begin 
			
				//after computing final a to g, adding them to origianl h1 to h7. them processing another block.
				{h0,h1,h2,h3,h4,h5,h6,h7} <= {a+h0,b+h1,c+h2,d+h3,e+h4,f+h5,g+h6,h+h7};
				state <= BLOCK;
				j <= j+1;
			end
    end

    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin
	if (offset < 8) begin
	
			
	
			cur_we <= 1;
			cur_addr <= output_addr-1;
			state <= WRITE;
			case (offset)
				0: cur_write_data <= h0;
				1: cur_write_data <= h1;
				2: cur_write_data <= h2;
				3: cur_write_data <= h3;
				4: cur_write_data <= h4;
				5: cur_write_data <= h5;
				6: cur_write_data <= h6;
				7: cur_write_data <= h7;
			endcase
			offset <= offset + 1;
		end
		else state <= IDLE;
    end



   endcase
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
