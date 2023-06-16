package com.example.controller.jpa;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.dto.MemberUser;
import com.example.entity.DesignOne;
import com.example.entity.File;
import com.example.entity.HomeAsk;
import com.example.entity.Member;
import com.example.entity.MemberAddress;
import com.example.entity.MemberFileView;
import com.example.entity.Orders;
import com.example.entity.Printing;
import com.example.entity.PrintingSide;
import com.example.entity.Tshirt;
import com.example.entity.TshirtColor;
import com.example.entity.TshirtSize;
import com.example.repository.DesignOneRepository;
import com.example.repository.FileRepository;
import com.example.repository.HomeAskRepository;
import com.example.repository.MemberAddressRepository;
import com.example.repository.MemberFileViewRepository;
import com.example.repository.MemberRepository;
import com.example.repository.OrdersRepository;
import com.example.repository.PrintingRepository;
import com.example.repository.PrintingSideRepository;
import com.example.repository.TsDesignViewRepository;
import com.example.repository.TsOrdersDesignViewRepository;
import com.example.repository.TshirtColorRepository;
import com.example.repository.TshirtDesignViewRepository;
import com.example.repository.TshirtRepository;
import com.example.repository.TshirtSizeRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@Slf4j
@RequiredArgsConstructor
@RequestMapping(value = "/member")
public class MemberController {

    final String format = "고객컨트롤러 => {}";
    final MemberRepository mRepository;
    final TshirtDesignViewRepository tdvRepository;
    final TsDesignViewRepository tsdvRepository;
    final DesignOneRepository dOneRepository;

    final MemberFileViewRepository mfvRepository;
    final TsOrdersDesignViewRepository tsOdvRepository;
    final OrdersRepository ordersRepository;
    final TshirtColorRepository tcRepository;
    final TshirtSizeRepository tsRepository;
    final TshirtRepository tRepository;
    final PrintingRepository pRepository;
    final PrintingSideRepository psRepository;
    final FileRepository fRepository;

    final ResourceLoader resourceLoader;

    final HomeAskRepository hAskRepository;

    final MemberAddressRepository mAddRepository;

    @GetMapping(value = "/image2")
    public ResponseEntity<byte[]> image2(@RequestParam(name = "fno", defaultValue = "0") BigInteger fno) throws IOException{
        File obj = fRepository.findById(fno).orElse(null);
        //log.info("objobj => {}", obj);
        HttpHeaders headers = new HttpHeaders(); // import org.springframework.http.HttpHeaders;
        if(obj != null){ // 이미지가 존재하는지 확인
            if(obj.getFsize() != null){
                headers.setContentType( MediaType.parseMediaType(obj.getFtype()));
                return new ResponseEntity<>(obj.getFdata(), headers, HttpStatus.OK);
            }
        }
        // 이미지가 없을 경우
        InputStream is = resourceLoader.getResource("./img/no-image.png").getInputStream(); //?
        headers.setContentType(MediaType.IMAGE_PNG);
        return new ResponseEntity<>(is.readAllBytes(), headers, HttpStatus.OK);
    }


    @GetMapping(value = "/mypage.do")
    public String mypageGET(
        Model model, 
        HttpServletRequest request,
        @AuthenticationPrincipal MemberUser user,
        @RequestParam(name="menu", required = false, defaultValue = "0") int menu
    ){
        try {
            if(user != null){ // 로그인 되었음
                    log.info("로그인user => {}", user); 
                    //로그인user => MemberUser(username=aaa, authorities=[ROLE_MEMBER], name=aaa)
                }
            model.addAttribute("user", user);

            if(menu ==1 || menu == 0){
                // log.info(format, user.getUsername());
                // 세션에서 아이디정보 꺼내서 mapper에 조회
                List<DesignOne> obj = dOneRepository.findByMember_MidOrderByDnoDesc(user.getUsername());
                // log.info("TshirtDesignView => {}", obj);
                model.addAttribute("obj", obj);
            }

            if(menu == 2){
                List<MemberFileView> obj2 = mfvRepository.findByMidOrderByDnoDesc(user.getUsername());
                for(MemberFileView obj2a : obj2){
                    if( obj2 != null ){ 
                        obj2a.setImageUrl1(request.getContextPath() + "/product/image2?fno=" + obj2a.getFno());
                    }
                }
                log.info("TshirtDesignView => {}", obj2);
                model.addAttribute("obj2", obj2);
            }

            if(menu == 3){
                List<Orders> obj3 = ordersRepository.findByDesignOne_Member_MidOrderByOno(user.getUsername());
                for(Orders orders : obj3){
                    TshirtColor tcolor = tcRepository.findByTcolorno(orders.getDesignOne().getTcolorno());
                    orders.setTcolorname(tcolor.getTcolorname());
                    log.info("컬러 => {}", orders.getTcolorname());

                    TshirtSize tSize = tsRepository.findByTsno(orders.getDesignOne().getTsno());
                    orders.setTssize(tSize.getTssize());

                    Tshirt tshirt = tRepository.findByTno(orders.getDesignOne().getTshirt().getTno());
                    orders.setTname(tshirt.getTname());
                    orders.setTprice(tshirt.getTprice());

                    Printing printing = pRepository.findBypno(orders.getDesignOne().getPrinting().getPno());
                    orders.setPmethod(printing.getPmethod());
                    orders.setPprice(printing.getPprice());

                    PrintingSide pside = psRepository.findByPsno(orders.getDesignOne().getPrintingSide().getPsno());
                    orders.setPsidename(pside.getPsidename());
                    
                    File file = fRepository.findByFno(orders.getDesignOne().getFile().getFno());
                    orders.setFno(file.getFno());
                    // log.info("주문목록 => {}", orders);
                }
                log.info("주문목록 => {}", obj3);
                
                model.addAttribute("obj3", obj3);
            }

            // 문의내역확인
            if(menu == 4){
                List<HomeAsk> hAsks = hAskRepository.findByMid(user.getUsername());
                log.info("문의목록 => {}", hAsks);
                model.addAttribute("hAsks", hAsks);
            }

            // 개인정보 변경 get
            if(menu == 5){
                Member obj = mRepository.findByMid(user.getUsername());
                // log.info("개인정보 => {}", obj);
                model.addAttribute("obj", obj);
            }

            // 개인정보 변경 get
            if(menu == 6){
                Member member = mRepository.findByMid(user.getUsername());
                List<MemberAddress> mAddList = mAddRepository.findByMember(member);
                // log.info("개인정보 => {}", obj);
                model.addAttribute("mAddList", mAddList);
            }

            return "/member/mypage";
        } catch (Exception e) {
            e.printStackTrace();
            return "home";
        }
    }

    @PostMapping(value = "/mypage")
    public String mypagePOST(
        Model model, 
        HttpServletRequest request,
        @AuthenticationPrincipal MemberUser user,
        @RequestParam(name="menu", required = false, defaultValue = "0") int menu
    ){
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
            }
            model.addAttribute("user", user);

            return "redirect:/mypage.do";
        } catch (Exception e) {
            e.printStackTrace();
            return "home";
        }
    }

    @PostMapping(value = "/withdraw.do")
    public String withdrawPOST(
        Model model, 
        @RequestParam(name="mpw") String mpw,
        @AuthenticationPrincipal MemberUser user
    ){
        try {
            // log.info("휴대폰번호 => {}", mphone);
            Member member = mRepository.findByMid(user.getUsername());

            BCryptPasswordEncoder bcpe = new BCryptPasswordEncoder();
            if(bcpe.matches(mpw, member.getMpw())){
                member.setMemail(null);
                member.setMname(null);
                member.setMphone(null);
                member.setMpw(null);
                member.setMregdate(null);

                mRepository.save(member);
                
            }
            // 로그아웃을 시켜야하는데용
            
            return "redirect:/home.do";
        } catch (Exception e) {
            e.printStackTrace();
            return "home";
        }
    }

    @PostMapping(value = "/update.do")
    public String updatePOST(
        Model model, 
        // @RequestParam(name="mid") String mid,
        @RequestParam(name="mname") String mname,
        @RequestParam(name="mphone") String mphone,
        @RequestParam(name="memail") String memail,
        @RequestParam(name="mpw") String mpw,
        HttpServletRequest request,
        @AuthenticationPrincipal MemberUser user,
        @RequestParam(name="menu", required = false, defaultValue = "0") int menu
    ){
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
            }
            model.addAttribute("user", user);
            
            // log.info("휴대폰번호 => {}", mphone);
            Member member = mRepository.findByMid(user.getUsername());

            BCryptPasswordEncoder bcpe = new BCryptPasswordEncoder();
            if(bcpe.matches(mpw, member.getMpw())){
                member.setMemail(memail);
                member.setMname(mname);
                member.setMphone(mphone);

                mRepository.save(member);
            }

            return "redirect:/member/mypage.do?menu=5";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/home.do";
        }
    }

    @GetMapping(value = "/updatepw.do")
    public String updatepwGET(
        Model model, 
        HttpServletRequest request,
        @AuthenticationPrincipal MemberUser user
    ){
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
                //로그인user => MemberUser(username=aaa, authorities=[ROLE_MEMBER], name=aaa)
            }
            model.addAttribute("user", user);

            Member member = mRepository.findByMid(user.getUsername());

            // log.info("개인정보 => {}", member);
            model.addAttribute("obj", member);

            return "/member/updatepw";
        } catch (Exception e) {
            e.printStackTrace();
            return "home";
        }
    }

    @PostMapping(value = "/updatepw.do")
    public String updatepwPOST(
        Model model, 
        @RequestParam(name="mpw") String mpw,
        @RequestParam(name="mpwnew") String mpwnew,
        @RequestParam(name="mpwnew1") String mpwnew1,
        HttpServletRequest request,
        HttpServletResponse response,
        @AuthenticationPrincipal MemberUser user
    ){
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
            }
            model.addAttribute("user", user);

            log.info("비번=> {}", mpw);
            log.info("새 비번=> {}", mpwnew1);
            
            Member member = mRepository.findByMid(user.getUsername());
            BCryptPasswordEncoder bcpe = new BCryptPasswordEncoder();
            if(bcpe.matches(mpw, member.getMpw())){
                log.info("YES => {}", "YES!!!!!");

                if(mpwnew.equals(mpwnew1)){
                log.info("REALLY => {}", "YES!!!!!");

                    member.setMpw(bcpe.encode(mpwnew1));
                    mRepository.save(member); // 비밀번호 변경 후 회원 정보 저장

                    // 비번 변경 성공시 로그아웃 성공
                    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                    if (auth != null) {
                        new SecurityContextLogoutHandler().logout(request, response, auth);
                    }
                }
            }
            log.info("저기요=> {}", member);
            return "redirect:/home.do";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/home.do";
        }
    }

    @PostMapping(value = "/dropmadd.do")
    public String dropmaddPOST(
        @RequestParam(name="ano") BigInteger ano
    ){
        try {
            log.info("ano => {}", ano);
            mAddRepository.deleteByAno(ano);
            return "redirect:/member/mypage.do?menu=6";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/home.do";
        }
    }

    @GetMapping(value = "/image")
    public ResponseEntity<byte[]> image(@RequestParam(name = "fno", defaultValue = "0") BigInteger fno) throws IOException{
        File obj = fRepository.findById(fno).orElse(null);
        //log.info("objobj => {}", obj);
        HttpHeaders headers = new HttpHeaders(); // import org.springframework.http.HttpHeaders;
        if(obj != null){ // 이미지가 존재하는지 확인
            if(obj.getFsize() != null){
                headers.setContentType( MediaType.parseMediaType(obj.getFtype()));
                return new ResponseEntity<>(obj.getFdata(), headers, HttpStatus.OK);
            }
        }
        // 이미지가 없을 경우
        InputStream is = resourceLoader.getResource("./img/no-image.png").getInputStream(); //?
        headers.setContentType(MediaType.IMAGE_PNG);
        return new ResponseEntity<>(is.readAllBytes(), headers, HttpStatus.OK);
    }
    
    @GetMapping(value = "/image.do")
    public String imageGET(
        @RequestParam(name="fno") BigInteger fno, 
        Model model, 
        HttpServletRequest request,
        @AuthenticationPrincipal MemberUser user
        ){
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
                //로그인user => MemberUser(username=aaa, authorities=[ROLE_MEMBER], name=aaa)
                }
            model.addAttribute("user", user);
            
            File obj2 = fRepository.findByFno(fno);
            if( obj2 != null ){ 
                obj2.setImageUrl1(request.getContextPath() + "/product/image2?fno=" + obj2.getFno());
            }
            model.addAttribute("obj2", obj2);

            log.info("아왜안나와 => {}", obj2);

            return "/member/image";
        } catch (Exception e) {
            e.printStackTrace();
            return "home";
        }
    }

}
